//! ACME wildcard certificate manager (Let's Encrypt via DNS-01).
//!
//! One wildcard certificate (`*.<domain>` + the apex) is issued over the ACME
//! DNS-01 challenge, with Cloudflare hosting the `_acme-challenge` TXT records.
//! The issued chain/key and the ACME account are cached under `state_dir` so a
//! restart reuses them and a renewal is a hot-swap, never a restart.
//!
//! Boot policy ladder — the relay must always come up:
//! * cached cert still valid → install it, schedule renewal at ~30 days to expiry
//! * cached cert expired/missing → install a self-signed stopgap, then try to
//!   issue in the background, retrying every few minutes until it succeeds
//!
//! The renewal task owns the [`SniResolver`] hot-swap, so issuance latency never
//! blocks the listener.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use tokio_util::sync::CancellationToken;

use crate::dns_cloudflare::{Cloudflare, TxtRecord};
use crate::tls::{self, SniResolver};

/// A cached ACME account tagged with the directory it was registered against,
/// so we never reuse a staging account in production (or vice versa).
#[derive(serde::Serialize, serde::Deserialize)]
struct CachedAccount {
    directory: String,
    credentials: AccountCredentials,
}

/// Renew once the leaf is within this window of expiry.
const RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Back-off between failed issuance attempts (boot ladder / renewal retry).
const RETRY_AFTER: Duration = Duration::from_secs(5 * 60);
/// Cap how long we wait for a single TXT to show up on Cloudflare's resolver.
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(150);

/// Everything the manager needs to issue and renew the wildcard certificate.
#[derive(Clone)]
pub struct AcmeManager {
    domain: String,
    state_dir: PathBuf,
    email: String,
    directory_url: String,
    cf_zone_id: String,
    cf_token: String,
}

impl AcmeManager {
    /// Build a manager from the resolved ACME config.
    pub fn new(
        domain: String,
        state_dir: PathBuf,
        email: String,
        staging: bool,
        cf_zone_id: String,
        cf_token: String,
    ) -> Self {
        let directory_url = if staging {
            LetsEncrypt::Staging.url().to_owned()
        } else {
            LetsEncrypt::Production.url().to_owned()
        };
        Self {
            domain,
            state_dir,
            email,
            directory_url,
            cf_zone_id,
            cf_token,
        }
    }

    fn cert_path(&self) -> PathBuf {
        self.state_dir.join("cert.pem")
    }
    fn key_path(&self) -> PathBuf {
        self.state_dir.join("key.pem")
    }
    fn account_path(&self) -> PathBuf {
        self.state_dir.join("account.json")
    }

    /// Load a cached chain+key if both files exist and parse. Returns the bytes.
    fn load_cached(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let cert = std::fs::read(self.cert_path()).ok()?;
        let key = std::fs::read(self.key_path()).ok()?;
        tls::certified_key_from_pem(&cert, &key).ok()?;
        Some((cert, key))
    }

    /// Create the state directory if needed, restricting it to the owner on unix
    /// (`0700`) so the cached key/account never rely solely on per-file mode.
    fn ensure_state_dir(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.state_dir)
            .with_context(|| format!("creating {}", self.state_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.state_dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("securing {}", self.state_dir.display()))?;
        }
        Ok(())
    }

    /// Persist the issued chain+key with tight permissions on the key.
    fn save(&self, cert_pem: &str, key_pem: &str) -> anyhow::Result<()> {
        self.ensure_state_dir()?;
        atomic_write(&self.cert_path(), cert_pem.as_bytes(), 0o644)?;
        atomic_write(&self.key_path(), key_pem.as_bytes(), 0o600)?;
        Ok(())
    }

    /// Install whatever certificate we can right now (cached or self-signed) and
    /// spawn the background issue/renew loop. Returns the DER of whatever leaf is
    /// serving immediately, so tests/callers can trust it.
    pub fn boot(
        self,
        resolver: Arc<SniResolver>,
        cancel: CancellationToken,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        tls::ensure_crypto_provider();
        let immediate_der = match self.load_cached() {
            Some((cert, key)) => {
                let ck = tls::certified_key_from_pem(&cert, &key)?;
                resolver.install(ck);
                match tls::cert_not_after(&cert) {
                    Ok(exp) => tracing::info!(
                        domain = %self.domain,
                        expires = ?exp,
                        "acme: serving cached wildcard certificate"
                    ),
                    Err(e) => tracing::warn!(error = %e, "acme: cached cert expiry unreadable"),
                }
                tls::first_cert_der(&cert).ok()
            }
            None => {
                let (ck, der) = tls::self_signed(&self.domain)?;
                resolver.install(ck);
                tracing::warn!(
                    domain = %self.domain,
                    "acme: no cached certificate; serving self-signed stopgap while issuing"
                );
                Some(der)
            }
        };

        let manager = Arc::new(self);
        tokio::spawn(manager.run(resolver, cancel));
        Ok(immediate_der)
    }

    /// The background loop: ensure a fresh cert is installed, sleep until the
    /// renewal window, repeat. Failures fall back to a fixed retry interval.
    async fn run(self: Arc<Self>, resolver: Arc<SniResolver>, cancel: CancellationToken) {
        loop {
            let wait = match self.ensure_cert(&resolver).await {
                Ok(until) => {
                    tracing::info!(next_check = ?until, "acme: certificate current");
                    until
                }
                Err(e) => {
                    tracing::warn!(error = %e, "acme: issuance failed; retrying");
                    RETRY_AFTER
                }
            };
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(wait) => {}
            }
        }
        tracing::debug!("acme: renewal task stopped");
    }

    /// Install a valid cert if the cached one is missing or within the renewal
    /// window. Returns how long to sleep before the next check.
    async fn ensure_cert(&self, resolver: &SniResolver) -> anyhow::Result<Duration> {
        if let Some((cert, _key)) = self.load_cached() {
            if let Ok(not_after) = tls::cert_not_after(&cert) {
                let remaining = not_after
                    .duration_since(SystemTime::now())
                    .unwrap_or(Duration::ZERO);
                if remaining > RENEW_BEFORE {
                    // Already installed at boot; just compute the next wake-up.
                    return Ok(remaining - RENEW_BEFORE);
                }
                tracing::info!(
                    ?remaining,
                    "acme: certificate within renewal window; renewing"
                );
            }
        }

        let (cert_pem, key_pem) = self.issue().await.context("issuing wildcard certificate")?;
        self.save(&cert_pem, &key_pem)?;
        let ck = tls::certified_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
        resolver.install(ck);
        let not_after = tls::cert_not_after(cert_pem.as_bytes())?;
        tracing::info!(domain = %self.domain, expires = ?not_after, "acme: new wildcard installed");
        let remaining = not_after
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        Ok(remaining
            .saturating_sub(RENEW_BEFORE)
            .max(Duration::from_secs(3600)))
    }

    /// Load a cached ACME account or register a new one, caching its credentials.
    async fn account(&self) -> anyhow::Result<Account> {
        // Reuse a cached account only if it belongs to the *same* ACME directory.
        // An account is bound to its directory, so a staging account must never
        // be reused after switching to production (or vice versa).
        if let Ok(bytes) = std::fs::read(self.account_path()) {
            if let Ok(cached) = serde_json::from_slice::<CachedAccount>(&bytes) {
                if cached.directory == self.directory_url {
                    let account = Account::builder()?
                        .from_credentials(cached.credentials)
                        .await?;
                    return Ok(account);
                }
                tracing::warn!("acme: cached account is for a different directory; re-registering");
            }
        }
        let contact = format!("mailto:{}", self.email);
        let (account, creds) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &[contact.as_str()],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.directory_url.clone(),
                None,
            )
            .await
            .context("creating ACME account")?;
        self.ensure_state_dir()?;
        let json = serde_json::to_vec(&CachedAccount {
            directory: self.directory_url.clone(),
            credentials: creds,
        })?;
        atomic_write(&self.account_path(), &json, 0o600)?;
        tracing::info!("acme: registered a new ACME account");
        Ok(account)
    }

    /// Run one full DNS-01 issuance, returning (cert chain PEM, key PEM).
    async fn issue(&self) -> anyhow::Result<(String, String)> {
        let account = self.account().await?;
        let cf = Cloudflare::new(self.cf_zone_id.clone(), self.cf_token.clone());

        let identifiers = vec![
            Identifier::Dns(self.domain.clone()),
            Identifier::Dns(format!("*.{}", self.domain)),
        ];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .context("creating ACME order")?;

        // Pass 1: collect the TXT records each pending authorization needs.
        let mut wanted: Vec<(String, String)> = Vec::new();
        {
            let mut auths = order.authorizations();
            while let Some(result) = auths.next().await {
                let mut authz = result?;
                if authz.status == AuthorizationStatus::Valid {
                    continue;
                }
                let challenge = authz
                    .challenge(ChallengeType::Dns01)
                    .ok_or_else(|| anyhow!("authorization has no DNS-01 challenge"))?;
                let base = match challenge.identifier().identifier {
                    Identifier::Dns(d) => d.strip_prefix("*.").unwrap_or(d).to_owned(),
                    other => bail!("unexpected identifier type: {other:?}"),
                };
                let value = challenge.key_authorization().dns_value();
                wanted.push((format!("_acme-challenge.{base}"), value));
            }
        }

        // Provision every TXT, then wait for all of them to be visible.
        let mut created: Vec<TxtRecord> = Vec::new();
        let issue_result = self
            .provision_and_finalize(&cf, &mut order, &wanted, &mut created)
            .await;

        // Always clean up the challenge records, success or failure.
        for rec in &created {
            if let Err(e) = cf.delete_record(&rec.id).await {
                tracing::warn!(record = %rec.name, error = %e, "acme: TXT cleanup failed");
            }
        }
        issue_result
    }

    /// The middle of [`issue`]: set TXTs, wait, mark ready, finalize, download.
    /// Split out so the caller can always run TXT cleanup afterward.
    async fn provision_and_finalize(
        &self,
        cf: &Cloudflare,
        order: &mut instant_acme::Order,
        wanted: &[(String, String)],
        created: &mut Vec<TxtRecord>,
    ) -> anyhow::Result<(String, String)> {
        for (name, value) in wanted {
            created.push(cf.create_txt(name, value).await?);
        }
        for (name, value) in wanted {
            cf.wait_propagated(name, value, PROPAGATION_TIMEOUT).await?;
        }

        // Pass 2: tell the CA every challenge is ready to validate.
        {
            let mut auths = order.authorizations();
            while let Some(result) = auths.next().await {
                let mut authz = result?;
                if authz.status == AuthorizationStatus::Valid {
                    continue;
                }
                let mut challenge = authz
                    .challenge(ChallengeType::Dns01)
                    .ok_or_else(|| anyhow!("authorization has no DNS-01 challenge"))?;
                challenge.set_ready().await?;
            }
        }

        let retry = RetryPolicy::default();
        let status = order.poll_ready(&retry).await.context("polling order")?;
        if status != OrderStatus::Ready {
            bail!("ACME order did not become ready (status {status:?})");
        }
        let key_pem = order.finalize().await.context("finalizing order")?;
        let cert_pem = order
            .poll_certificate(&retry)
            .await
            .context("downloading certificate")?;
        Ok((cert_pem, key_pem))
    }
}

/// Write `bytes` to `path` atomically (temp + rename) with the given unix mode.
///
/// The temp file is created with `mode` from the outset via `O_EXCL`, so the key
/// material is never momentarily world-readable in the window before a chmod, and
/// a pre-created file/symlink at the predictable temp path cannot be followed.
/// Errors are propagated rather than swallowed, so the key is never silently left
/// at the wrong mode.
fn atomic_write(path: &std::path::Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.sync_all().ok();
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}
