//! `etun admin doctor` — pre-flight diagnostics for a relay deployment.
//!
//! Everything here is read-only (the one exception, the Cloudflare DNS:Edit
//! probe, creates and immediately deletes a throwaway TXT). It is meant to be
//! the first thing you run on a fresh VPS: it tells you whether DNS, the
//! registry, and the ACME credentials are wired correctly *before* you depend on
//! the relay serving real traffic.

use std::time::SystemTime;

use crate::config::{Config, TlsMode};
use crate::dns_cloudflare::Cloudflare;
use crate::registry::Registry;

/// Severity of one check, for tidy reporting and the pass/fail tally.
#[derive(PartialEq, Eq)]
enum Level {
    Pass,
    /// Advisory: surfaced but does NOT count as a failure (e.g. something the
    /// doctor cannot verify from here and the operator must check manually).
    Warn,
    Fail,
}

/// Outcome of one check, for tidy reporting.
struct Check {
    level: Level,
    label: String,
    detail: String,
}

impl Check {
    fn pass(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            level: Level::Pass,
            label: label.into(),
            detail: detail.into(),
        }
    }
    fn warn(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            level: Level::Warn,
            label: label.into(),
            detail: detail.into(),
        }
    }
    fn fail(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            level: Level::Fail,
            label: label.into(),
            detail: detail.into(),
        }
    }
    /// Only a hard `Fail` counts against the doctor's exit status; warnings are
    /// advisories the operator must act on but don't fail the pre-flight.
    fn is_fail(&self) -> bool {
        self.level == Level::Fail
    }
    fn print(&self) {
        let mark = match self.level {
            Level::Pass => "ok  ",
            Level::Warn => "WARN",
            Level::Fail => "FAIL",
        };
        println!("[{mark}] {:<22} {}", self.label, self.detail);
    }
}

/// Run all relay diagnostics. Returns true iff every critical check passed.
pub async fn run(config: &Config) -> bool {
    let mut checks: Vec<Check> = Vec::new();

    // --- config + registry ---
    checks.push(Check::pass(
        "config",
        format!("domain = {}", config.server.domain),
    ));

    match Registry::open(&config.registry.db_path, &config.server.domain) {
        Ok(reg) => match reg.integrity_check() {
            Ok(()) => checks.push(Check::pass(
                "registry",
                format!("{} integrity ok", config.registry.db_path.display()),
            )),
            Err(e) => checks.push(Check::fail(
                "registry",
                format!("integrity check failed: {e}"),
            )),
        },
        Err(e) => checks.push(Check::fail(
            "registry",
            format!("cannot open {}: {e}", config.registry.db_path.display()),
        )),
    }

    // --- DNS: apex, control endpoint, and the wildcard ---
    let apex = config.server.domain.clone();
    checks.push(dns_check("dns apex", &apex).await);
    checks.push(dns_check("dns connect", &config.connect_host()).await);
    // Any label under the apex should resolve if the wildcard A record exists.
    checks.push(dns_check("dns wildcard", &format!("etun-doctor-check.{apex}")).await);

    // --- TLS material readiness (what would actually be served) ---
    checks.push(tls_check(config));

    // --- raw-TCP reachability (advisory; cannot be verified from here) ---
    // HTTPS tunnels need only :443 inbound, but raw-TCP tunnels are served on the
    // configured port range, which must be opened inbound on BOTH the host
    // firewall and the cloud security group. The doctor has no way to probe its
    // own external reachability, so this is a WARN the operator must act on, not
    // a pass/fail. See deploy/DEPLOY.md "Firewall / raw-TCP".
    let [lo, hi] = config.tcp.port_range;
    checks.push(Check::warn(
        "raw-tcp firewall",
        format!(
            "raw-TCP tunnels need ports {lo}-{hi}/tcp open INBOUND on the host \
             firewall + cloud security group (HTTPS tunnels need only :443); \
             this cannot be verified externally — see DEPLOY.md"
        ),
    ));

    // --- ACME credentials (only meaningful in acme mode) ---
    if config.tls.mode == TlsMode::Acme {
        match &config.tls.acme {
            None => checks.push(Check::fail(
                "acme config",
                "tls.mode=acme but [tls.acme] missing",
            )),
            Some(acme) => match acme.cloudflare.token() {
                Err(e) => checks.push(Check::fail("acme token", e.to_string())),
                Ok(token) => {
                    checks.push(Check::pass(
                        "acme token",
                        format!("read {}", acme.cloudflare.api_token_file.display()),
                    ));
                    let cf = Cloudflare::new(acme.cloudflare.zone_id.clone(), token);
                    match cf.verify_dns_edit(&apex).await {
                        Ok(()) => checks.push(Check::pass(
                            "cloudflare",
                            "Zone:DNS:Edit confirmed (probe TXT)",
                        )),
                        Err(e) => checks.push(Check::fail("cloudflare", e.to_string())),
                    }
                }
            },
        }
    }

    println!("\nEtherTunnel relay doctor — {}\n", config.server.domain);
    for c in &checks {
        c.print();
    }
    let failed = checks.iter().filter(|c| c.is_fail()).count();
    let warned = checks.iter().filter(|c| c.level == Level::Warn).count();
    if failed == 0 {
        if warned > 0 {
            println!("\nAll critical checks passed ({warned} warning(s) — review above).");
        } else {
            println!("\nAll checks passed.");
        }
        true
    } else {
        println!("\n{failed} check(s) failed.");
        false
    }
}

/// Resolve `host:443`; a success means at least one A/AAAA record exists.
async fn dns_check(label: &str, host: &str) -> Check {
    match tokio::net::lookup_host((host, 443u16)).await {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => Check::pass(label, format!("{host} -> {}", a.ip())),
            None => Check::fail(label, format!("{host} resolved to no addresses")),
        },
        Err(e) => Check::fail(label, format!("{host}: {e}")),
    }
}

/// Report on the certificate that would be served, by mode.
fn tls_check(config: &Config) -> Check {
    match config.tls.mode {
        TlsMode::SelfSigned => Check::pass("tls", "self-signed (development only)"),
        TlsMode::Manual => match &config.tls.manual {
            None => Check::fail("tls", "tls.mode=manual but [tls.manual] missing"),
            Some(m) => match std::fs::read(&m.cert_file) {
                Ok(pem) => expiry_detail("tls (manual)", &pem),
                Err(e) => Check::fail("tls (manual)", format!("{}: {e}", m.cert_file.display())),
            },
        },
        TlsMode::Acme => {
            let cached = config.tls.state_dir.join("cert.pem");
            match std::fs::read(&cached) {
                Ok(pem) => expiry_detail("tls (acme)", &pem),
                Err(_) => Check::pass(
                    "tls (acme)",
                    "no cached cert yet; will issue on first boot".to_owned(),
                ),
            }
        }
    }
}

fn expiry_detail(label: &str, pem: &[u8]) -> Check {
    match crate::tls::cert_not_after(pem) {
        Ok(exp) => {
            let remaining = exp
                .duration_since(SystemTime::now())
                .map(|d| d.as_secs() / 86400)
                .unwrap_or(0);
            if remaining == 0 {
                Check::fail(label, "certificate has expired".to_owned())
            } else {
                Check::pass(label, format!("valid, ~{remaining} days remaining"))
            }
        }
        Err(e) => Check::fail(label, format!("unreadable certificate: {e}")),
    }
}
