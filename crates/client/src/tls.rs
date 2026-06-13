//! Client-side TLS configuration.
//!
//! Daemons verify the relay's certificate like any HTTPS client. Production
//! uses the bundled Mozilla root set; a `CustomRoot` lets a self-hoster trust a
//! private-CA or self-signed relay (and lets tests trust the relay's generated
//! cert). A fuller build can swap in `rustls-platform-verifier` for true OS
//! trust stores; the Mozilla bundle is correct and dependency-light for now.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

/// How the daemon decides whether to trust the relay's certificate.
#[derive(Clone, Debug)]
pub enum TrustMode {
    /// Trust the bundled Mozilla root CAs (production, Let's Encrypt relays).
    System,
    /// Trust exactly this certificate DER (self-signed/private-CA relays, tests).
    CustomRoot(Vec<u8>),
}

/// Install the ring crypto provider as process default (idempotent).
pub fn ensure_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Build a rustls `ClientConfig` for the given trust mode, offering HTTP/1.1.
pub fn client_config(trust: &TrustMode) -> anyhow::Result<Arc<ClientConfig>> {
    ensure_crypto_provider();
    let mut roots = RootCertStore::empty();
    match trust {
        TrustMode::System => {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        TrustMode::CustomRoot(der) => {
            roots
                .add(CertificateDer::from(der.clone()))
                .map_err(|e| anyhow::anyhow!("invalid relay CA certificate: {e}"))?;
        }
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
