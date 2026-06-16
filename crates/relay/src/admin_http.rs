//! The keygate-authenticated provisioning control plane.
//!
//! These endpoints are the relay's *first inbound control-plane HTTP API*. They
//! are mounted as `POST /admin/*` on `connect.<domain>` (so they ride the same
//! TLS cert and listener as the WebSocket control upgrade — method+path
//! discriminate the two: the WS upgrade is `GET` + Upgrade headers, these are
//! `POST` + a JSON body). The sole caller is keygate, over TLS to this public
//! host, presenting a 256-bit shared bearer token.
//!
//! Security posture (mirrors the registry/push.rs discipline):
//! * Bearer compared with [`subtle::ConstantTimeEq`].
//! * Request body capped hard before we read or parse it (the connection's
//!   slowloris header timeout already bounds how long headers may take).
//! * The minted relay token (`etun_…`) is returned in the response body but is
//!   **never logged** — only outcomes/status are traced.
//! * `Authenticator` is untouched; this reaches the concrete [`Registry`]
//!   through a dedicated, optional [`ProvisionState`] handle on `SessionCtx`,
//!   installed only when `[provision]` is configured.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{Request, StatusCode};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::proxy::{self, Resp};
use crate::registry::{Registry, RegistryError};
use crate::session::SessionCtx;

/// Hard cap on the provisioning request body. These payloads are tiny JSON
/// objects (`{"external_ref":"acct_…"}`); anything larger is rejected before we
/// buffer it, so an authenticated-or-not caller can't make us allocate.
const MAX_BODY: u64 = 4 * 1024;

/// Max length of an `external_ref` we accept as a relay username. The schema has
/// no charset constraint on `users.name`, but we still bound length and require
/// printable ASCII so an opaque keygate-generated id is the only thing that maps
/// cleanly to a username.
const MAX_EXTERNAL_REF: usize = 64;

/// Installed on `SessionCtx` when `[provision]` is configured. Holds the
/// concrete registry (the `Authenticator` trait object can't mint tokens) plus
/// the shared bearer token keygate must present.
pub struct ProvisionState {
    pub registry: Arc<Registry>,
    pub token: String,
}

#[derive(Deserialize)]
struct ProvisionReq {
    external_ref: String,
}

#[derive(Serialize)]
struct ProvisionResp {
    token: String,
    created: bool,
}

#[derive(Serialize)]
struct RotateResp {
    token: String,
    /// How many previously-valid tokens were revoked by this rotation.
    revoked: usize,
}

#[derive(Deserialize)]
struct ReleaseReq {
    external_ref: String,
    #[serde(default)]
    release_ports: bool,
}

#[derive(Serialize)]
struct ReleaseResp {
    released_hostnames: Vec<String>,
    released_ports: Vec<u16>,
}

/// True iff `req` targets the provisioning control plane (so the listener should
/// route it here instead of treating it as a visitor/upgrade request). Only
/// matches when provisioning is actually configured.
pub fn is_admin_request(ctx: &SessionCtx, req: &Request<hyper::body::Incoming>) -> bool {
    ctx.provision.load().is_some()
        && req.method() == hyper::Method::POST
        && req.uri().path().starts_with("/admin/")
}

/// Dispatch a `/admin/*` provisioning request. Always returns a response (never
/// errors out of band). Auth is checked first, constant-time.
pub async fn handle(ctx: Arc<SessionCtx>, req: Request<hyper::body::Incoming>) -> Resp {
    let Some(state) = ctx.provision.load_full() else {
        // Provisioning not configured: behave as if the route doesn't exist.
        return json(StatusCode::NOT_FOUND, &err("not_found"));
    };

    if !authorized(&state, &req) {
        return json(StatusCode::UNAUTHORIZED, &err("unauthorized"));
    }

    let path = req.uri().path().to_owned();
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    match path.as_str() {
        "/admin/provision" => handle_provision(&state, &body),
        "/admin/rotate" => handle_rotate(&state, &body),
        "/admin/release" => handle_release(&state, &body),
        _ => json(StatusCode::NOT_FOUND, &err("not_found")),
    }
}

fn handle_provision(state: &ProvisionState, body: &[u8]) -> Resp {
    let req: ProvisionReq = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return json(StatusCode::BAD_REQUEST, &err("invalid_json")),
    };
    if !valid_ref(&req.external_ref) {
        return json(StatusCode::BAD_REQUEST, &err("invalid_external_ref"));
    }
    match state.registry.provision_user_token(&req.external_ref) {
        Ok((token, created)) => {
            // NEVER log the token; only the outcome.
            tracing::info!(external_ref = %req.external_ref, created, "provisioned relay account");
            json(StatusCode::OK, &ProvisionResp { token, created })
        }
        Err(e) => {
            tracing::error!(external_ref = %req.external_ref, error = %e, "provision failed");
            json(StatusCode::INTERNAL_SERVER_ERROR, &err("db_error"))
        }
    }
}

/// `POST /admin/rotate` — revoke every valid token for the account and mint one
/// fresh token. Used by keygate's self-serve *recovery* path so a recovered
/// account's leaked/lost tokens stop working. Reuses [`ProvisionReq`] (the body
/// is just `{"external_ref":"acct_…"}`).
fn handle_rotate(state: &ProvisionState, body: &[u8]) -> Resp {
    let req: ProvisionReq = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return json(StatusCode::BAD_REQUEST, &err("invalid_json")),
    };
    if !valid_ref(&req.external_ref) {
        return json(StatusCode::BAD_REQUEST, &err("invalid_external_ref"));
    }
    match state.registry.rotate_user_token(&req.external_ref) {
        Ok((token, revoked)) => {
            // NEVER log the token; only the outcome (incl. how many were killed).
            tracing::info!(external_ref = %req.external_ref, revoked, "rotated relay account token");
            json(StatusCode::OK, &RotateResp { token, revoked })
        }
        Err(e) => {
            tracing::error!(external_ref = %req.external_ref, error = %e, "rotate failed");
            json(StatusCode::INTERNAL_SERVER_ERROR, &err("db_error"))
        }
    }
}

fn handle_release(state: &ProvisionState, body: &[u8]) -> Resp {
    let req: ReleaseReq = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return json(StatusCode::BAD_REQUEST, &err("invalid_json")),
    };
    if !valid_ref(&req.external_ref) {
        return json(StatusCode::BAD_REQUEST, &err("invalid_external_ref"));
    }
    match state
        .registry
        .release_user_hostnames(&req.external_ref, req.release_ports)
    {
        Ok((released_hostnames, released_ports)) => {
            tracing::info!(
                external_ref = %req.external_ref,
                hostnames = released_hostnames.len(),
                ports = released_ports.len(),
                "released account namespace"
            );
            json(
                StatusCode::OK,
                &ReleaseResp {
                    released_hostnames,
                    released_ports,
                },
            )
        }
        Err(RegistryError::NoSuchUser(_)) => {
            // Already gone / never existed: idempotent success for the reaper.
            json(StatusCode::NOT_FOUND, &err("no_such_user"))
        }
        Err(e) => {
            tracing::error!(external_ref = %req.external_ref, error = %e, "release failed");
            json(StatusCode::INTERNAL_SERVER_ERROR, &err("db_error"))
        }
    }
}

/// Constant-time bearer check against the configured provisioning token.
fn authorized(state: &ProvisionState, req: &Request<hyper::body::Incoming>) -> bool {
    let presented = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        // ct_eq over equal-length byte slices; length is itself compared in
        // constant time by `ConstantTimeEq for [u8]` (it returns 0 on mismatch).
        Some(tok) => tok.as_bytes().ct_eq(state.token.as_bytes()).into(),
        None => false,
    }
}

/// An `external_ref` is a non-empty, bounded, printable-ASCII id (the only thing
/// keygate generates and the only thing that maps cleanly to a relay username).
fn valid_ref(external_ref: &str) -> bool {
    !external_ref.is_empty()
        && external_ref.len() <= MAX_EXTERNAL_REF
        && external_ref
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

/// Read the request body with a hard length cap, returning a 413 on overflow.
async fn read_body(req: Request<hyper::body::Incoming>) -> Result<Bytes, Resp> {
    // Reject up front if the advertised length already exceeds the cap.
    if let Some(len) = req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if len > MAX_BODY {
            return Err(json(StatusCode::PAYLOAD_TOO_LARGE, &err("body_too_large")));
        }
    }
    let limited = http_body_util::Limited::new(req.into_body(), MAX_BODY as usize);
    match limited.collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(_) => Err(json(StatusCode::PAYLOAD_TOO_LARGE, &err("body_too_large"))),
    }
}

fn err(code: &str) -> serde_json::Value {
    serde_json::json!({ "error": code })
}

fn json<T: Serialize>(status: StatusCode, body: &T) -> Resp {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| br#"{"error":"serialize"}"#.to_vec());
    proxy::page(status, "application/json", bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> ProvisionState {
        ProvisionState {
            registry: Arc::new(Registry::open_in_memory("ethertunnel.com").unwrap()),
            token: "secret-provision-token".to_owned(),
        }
    }

    #[test]
    fn valid_ref_rules() {
        assert!(valid_ref("acct_abc123"));
        assert!(!valid_ref(""));
        assert!(!valid_ref(&"a".repeat(65)));
        assert!(!valid_ref("has space"));
        assert!(!valid_ref("has\"quote"));
        assert!(!valid_ref("back\\slash"));
    }

    #[test]
    fn authorized_checks_bearer_constant_time() {
        let st = state();
        // Build requests over a generic empty body (not Incoming) to exercise the
        // header logic; `authorized` is generic-free but only reads headers, so
        // we replicate its check here against the same token bytes.
        let good = format!("Bearer {}", st.token);
        let bad = "Bearer wrong-token";
        let none = "";
        assert!(bearer_ok(&st, Some(&good)));
        assert!(!bearer_ok(&st, Some(bad)));
        assert!(!bearer_ok(&st, Some(none)));
        assert!(!bearer_ok(&st, None));
    }

    // Mirror of `authorized`'s logic operating on a raw header value, so the
    // constant-time bearer comparison is unit-tested without needing a real
    // `hyper::body::Incoming` (which has no public constructor).
    fn bearer_ok(state: &ProvisionState, header: Option<&str>) -> bool {
        match header.and_then(|v| v.strip_prefix("Bearer ")) {
            Some(tok) => tok.as_bytes().ct_eq(state.token.as_bytes()).into(),
            None => false,
        }
    }

    #[test]
    fn provision_then_release_roundtrip() {
        let st = state();
        // Provision mints a token and creates the user.
        let resp = handle_provision(&st, br#"{"external_ref":"acct_test1"}"#);
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(st
            .registry
            .list_users()
            .unwrap()
            .iter()
            .any(|(_, n, _)| n == "acct_test1"));

        // Claim a label so release has something to return.
        let uid = st.registry.list_users().unwrap()[0].0;
        st.registry.claim_label(uid, "demo").unwrap();

        let resp = handle_release(
            &st,
            br#"{"external_ref":"acct_test1","release_ports":true}"#,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(st
            .registry
            .list_hostnames(Some("acct_test1"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn rotate_revokes_old_tokens_via_route() {
        use crate::auth::Authenticator;
        let st = state();
        // Two valid tokens on the account, as the live system would have.
        let (old1, _) = st.registry.provision_user_token("acct_rot").unwrap();
        let (old2, _) = st.registry.provision_user_token("acct_rot").unwrap();
        assert!(st.registry.authenticate(&old1).is_some());
        assert!(st.registry.authenticate(&old2).is_some());

        let resp = handle_rotate(&st, br#"{"external_ref":"acct_rot"}"#);
        assert_eq!(resp.status(), StatusCode::OK);

        // Both prior tokens must now fail auth; the account still exists.
        assert!(st.registry.authenticate(&old1).is_none());
        assert!(st.registry.authenticate(&old2).is_none());
        assert_eq!(st.registry.list_users().unwrap().len(), 1);
    }

    #[test]
    fn rotate_bad_ref_is_rejected() {
        let st = state();
        let resp = handle_rotate(&st, br#"{"external_ref":""}"#);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = handle_rotate(&st, br#"{"not_ref":"x"}"#);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn provision_bad_ref_is_rejected() {
        let st = state();
        let resp = handle_provision(&st, br#"{"external_ref":""}"#);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = handle_provision(&st, br#"{"not_ref":"x"}"#);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn release_unknown_user_is_404() {
        let st = state();
        let resp = handle_release(&st, br#"{"external_ref":"acct_missing"}"#);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
