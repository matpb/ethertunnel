//! TLS material and SNI-based certificate resolution.
//!
//! The resolver is both the cert source and the first line of junk rejection:
//! a ClientHello whose SNI is not under our domain aborts the handshake before
//! we spend anything on it. The active certificate is held in an
//! [`ArcSwapOption`] so the ACME renewal task (M6) can hot-swap it without
//! restarting the listener; M2 installs a self-signed cert once.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// Resolves the wildcard certificate for any SNI under the relay's domain, and
/// rejects everything else at the handshake.
#[derive(Debug)]
pub struct SniResolver {
    cert: ArcSwapOption<CertifiedKey>,
    apex: String,
    suffix: String,
}

impl SniResolver {
    /// Create a resolver for `domain` with no certificate installed yet.
    pub fn new(domain: &str) -> Self {
        Self {
            cert: ArcSwapOption::from(None),
            apex: domain.to_owned(),
            suffix: format!(".{domain}"),
        }
    }

    /// Install (or hot-swap) the active certificate.
    pub fn install(&self, cert: Arc<CertifiedKey>) {
        self.cert.store(Some(cert));
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?;
        if name == self.apex || name.ends_with(&self.suffix) {
            self.cert.load_full()
        } else {
            // Out-of-domain SNI (scanners, misrouted traffic): abort cheaply.
            None
        }
    }
}

/// Generate a self-signed certificate covering `domain` and `*.domain`.
///
/// Returns the rustls signing material plus the certificate DER, so tests (and
/// the client's `relay_ca` option) can choose to trust it.
pub fn self_signed(domain: &str) -> anyhow::Result<(Arc<CertifiedKey>, Vec<u8>)> {
    let names = vec![domain.to_owned(), format!("*.{domain}")];
    let generated = rcgen::generate_simple_self_signed(names)?;
    let cert_der = generated.cert.der().to_vec();
    let key_der = generated.key_pair.serialize_der();

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(key_der),
    ))?;
    let certified = CertifiedKey::new(vec![CertificateDer::from(cert_der.clone())], signing_key);
    Ok((Arc::new(certified), cert_der))
}

/// Build a rustls `ServerConfig` that resolves certs via `resolver` and offers
/// only HTTP/1.1 over ALPN (WebSocket upgrade is HTTP/1.1; h2 is out of scope).
pub fn server_config(resolver: Arc<SniResolver>) -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Build a [`CertifiedKey`] from a PEM certificate chain and PEM private key.
/// Used by ACME (issued chain) and `manual` mode (operator-provided files).
pub fn certified_key_from_pem(
    chain_pem: &[u8],
    key_pem: &[u8],
) -> anyhow::Result<Arc<CertifiedKey>> {
    use rustls::pki_types::pem::PemObject;
    let certs = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("parsing certificate chain: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in PEM chain");
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|e| anyhow::anyhow!("parsing private key: {e}"))?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| anyhow::anyhow!("unsupported private key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// The first certificate (DER) in a PEM chain — handy for trusting in tests.
pub fn first_cert_der(chain_pem: &[u8]) -> anyhow::Result<Vec<u8>> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(chain_pem)
        .next()
        .and_then(|r| r.ok())
        .map(|c| c.as_ref().to_vec())
        .ok_or_else(|| anyhow::anyhow!("no certificate in PEM chain"))
}

/// The `notAfter` expiry of the leaf certificate in a PEM chain.
pub fn cert_not_after(chain_pem: &[u8]) -> anyhow::Result<std::time::SystemTime> {
    let der = first_cert_der(chain_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| anyhow::anyhow!("parsing leaf certificate: {e}"))?;
    let secs = cert.validity().not_after.timestamp();
    if secs < 0 {
        anyhow::bail!("certificate notAfter is before the unix epoch");
    }
    Ok(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
}

/// Install the ring crypto provider as process default (idempotent). Must run
/// before building any rustls config.
pub fn ensure_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_roundtrip_and_expiry() {
        ensure_crypto_provider();
        // Build a real cert/key PEM via rcgen, then load it back the way ACME and
        // manual mode do.
        let generated =
            rcgen::generate_simple_self_signed(vec!["ethertunnel.com".to_owned()]).unwrap();
        let cert_pem = generated.cert.pem();
        let key_pem = generated.key_pair.serialize_pem();

        let ck = certified_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
        assert!(!ck.cert.is_empty());

        let not_after = cert_not_after(cert_pem.as_bytes()).unwrap();
        assert!(
            not_after > std::time::SystemTime::now(),
            "fresh cert should expire in the future"
        );

        // Garbage in, error out (not a panic).
        assert!(certified_key_from_pem(b"not a pem", b"nope").is_err());
        assert!(cert_not_after(b"not a pem").is_err());
    }

    #[test]
    fn self_signed_builds_and_resolver_filters_by_domain() {
        ensure_crypto_provider();
        let (ck, der) = self_signed("ethertunnel.com").unwrap();
        assert!(!der.is_empty());

        let resolver = SniResolver::new("ethertunnel.com");
        resolver.install(ck);
        // The resolver only serves names under the domain; the actual SNI
        // matching is exercised end-to-end by the TLS integration test.
        assert_eq!(resolver.apex, "ethertunnel.com");
        assert_eq!(resolver.suffix, ".ethertunnel.com");
    }
}
