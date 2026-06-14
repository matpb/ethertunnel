//! Cloudflare DNS-01 provider for ACME wildcard issuance.
//!
//! Speaks just enough of the Cloudflare API v4 to create, find, and delete the
//! `_acme-challenge` TXT records Let's Encrypt checks during a DNS-01 challenge,
//! plus a DNS-over-HTTPS propagation probe so we never tell the CA to validate a
//! record that is not visible yet. It reuses the hyper-rustls stack instant-acme
//! already pulls (ring only), so no second TLS backend leaks into the static
//! musl build.

use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{json, Value};

const API: &str = "https://api.cloudflare.com/client/v4";
const DOH: &str = "https://cloudflare-dns.com/dns-query";

/// A Cloudflare API client scoped to one zone.
pub struct Cloudflare {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    zone_id: String,
    token: String,
}

/// A TXT record we created, remembered so we can delete it on cleanup.
#[derive(Debug, Clone)]
pub struct TxtRecord {
    pub id: String,
    pub name: String,
}

impl Cloudflare {
    /// Build a client for `zone_id` authenticating with `token`.
    pub fn new(zone_id: String, token: String) -> Self {
        // The DoH/API connector and every other rustls config share the process
        // default provider; make sure ring is installed even on the CLI path.
        crate::tls::ensure_crypto_provider();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);
        Self {
            client,
            zone_id,
            token,
        }
    }

    /// Make one authenticated JSON call against the Cloudflare API.
    async fn api(&self, method: Method, url: &str, body: Option<Value>) -> anyhow::Result<Value> {
        let payload = match &body {
            Some(v) => Bytes::from(serde_json::to_vec(v)?),
            None => Bytes::new(),
        };
        let req = Request::builder()
            .method(method)
            .uri(url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .header("User-Agent", "ethertunnel/0.1")
            .body(Full::new(payload))?;
        let resp = self
            .client
            .request(req)
            .await
            .context("cloudflare API request")?;
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .context("reading cloudflare response")?
            .to_bytes();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let ok = status.is_success() && json.get("success") != Some(&Value::Bool(false));
        if !ok {
            let errs = json.get("errors").cloned().unwrap_or(Value::Null);
            bail!("cloudflare API {status}: {errs}");
        }
        Ok(json)
    }

    /// Create a TXT record and return its id for later cleanup.
    pub async fn create_txt(&self, name: &str, content: &str) -> anyhow::Result<TxtRecord> {
        let url = format!("{API}/zones/{}/dns_records", self.zone_id);
        let body = json!({ "type": "TXT", "name": name, "content": content, "ttl": 60 });
        let json = self.api(Method::POST, &url, Some(body)).await?;
        let id = json["result"]["id"]
            .as_str()
            .ok_or_else(|| anyhow!("cloudflare response missing record id"))?
            .to_owned();
        Ok(TxtRecord {
            id,
            name: name.to_owned(),
        })
    }

    /// Delete a previously created record. Best-effort; logs but does not fail
    /// the issuance if cleanup fails (a stale `_acme-challenge` TXT is harmless).
    pub async fn delete_record(&self, id: &str) -> anyhow::Result<()> {
        let url = format!("{API}/zones/{}/dns_records/{id}", self.zone_id);
        self.api(Method::DELETE, &url, None).await?;
        Ok(())
    }

    /// Poll Cloudflare's public resolver (DoH) until `expected` shows up in the
    /// TXT answers for `name`, or `timeout` elapses. Because the zone is on
    /// Cloudflare, 1.1.1.1 reflects the authoritative record within seconds.
    pub async fn wait_propagated(
        &self,
        name: &str,
        expected: &str,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.txt_visible(name, expected).await.unwrap_or(false) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("TXT {name} did not propagate within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    /// One DoH TXT lookup; true if any answer equals `expected` exactly.
    async fn txt_visible(&self, name: &str, expected: &str) -> anyhow::Result<bool> {
        let url = format!("{DOH}?name={name}&type=TXT");
        let req = Request::builder()
            .method(Method::GET)
            .uri(&url)
            .header("Accept", "application/dns-json")
            .header("User-Agent", "ethertunnel/0.1")
            .body(Full::new(Bytes::new()))?;
        let resp = self.client.request(req).await.context("DoH request")?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) else {
            return Ok(false);
        };
        Ok(answers.iter().any(|a| {
            a.get("data")
                .and_then(|d| d.as_str())
                .map(|d| d.trim_matches('"') == expected)
                .unwrap_or(false)
        }))
    }

    /// Prove the token can actually edit DNS in this zone: create then delete a
    /// throwaway TXT. Used by `etun admin doctor`.
    pub async fn verify_dns_edit(&self, apex: &str) -> anyhow::Result<()> {
        let name = format!("_etun-probe.{apex}");
        let rec = self
            .create_txt(&name, "etun-doctor-probe")
            .await
            .context("creating probe TXT (token needs Zone:DNS:Edit)")?;
        self.delete_record(&rec.id)
            .await
            .context("deleting probe TXT")?;
        Ok(())
    }
}
