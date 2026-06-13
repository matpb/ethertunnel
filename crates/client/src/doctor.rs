//! `etun doctor` — diagnose a client's ability to reach and use its relay.

use crate::config::FileConfig;
use crate::{creds, login};

struct Check {
    ok: bool,
    label: String,
    detail: String,
}

impl Check {
    fn print(&self) {
        let mark = if self.ok { "ok  " } else { "FAIL" };
        println!("[{mark}] {:<16} {}", self.label, self.detail);
    }
}

fn pass(label: &str, detail: impl Into<String>) -> Check {
    Check {
        ok: true,
        label: label.into(),
        detail: detail.into(),
    }
}
fn fail(label: &str, detail: impl Into<String>) -> Check {
    Check {
        ok: false,
        label: label.into(),
        detail: detail.into(),
    }
}

/// Run client diagnostics. Returns true iff every critical check passed.
pub async fn run() -> bool {
    let mut checks = Vec::new();

    let cfg = match FileConfig::load() {
        Ok(c) => c,
        Err(e) => {
            println!("[FAIL] config           {e}");
            return false;
        }
    };

    if cfg.relay.is_empty() {
        checks.push(fail("config", "no relay set; run `etun login` first"));
        for c in &checks {
            c.print();
        }
        return false;
    }
    checks.push(pass("config", format!("relay = {}", cfg.relay)));
    checks.push(pass("tunnels", format!("{} configured", cfg.tunnels.len())));

    let token = creds::resolve(&cfg.relay).ok().flatten();
    match &token {
        Some(_) => checks.push(pass("credentials", "token present")),
        None => checks.push(fail("credentials", "no token; run `etun login`")),
    }

    let trust = match cfg.trust_mode() {
        Ok(t) => t,
        Err(e) => {
            checks.push(fail("trust", e.to_string()));
            for c in &checks {
                c.print();
            }
            return false;
        }
    };

    // TLS handshake + certificate expiry against the live relay.
    match login::tls_probe(&cfg.relay, &trust).await {
        Ok(info) if info.expired => checks.push(fail("relay tls", "certificate has expired")),
        Ok(info) => checks.push(pass(
            "relay tls",
            format!("valid, ~{} days remaining", info.days_remaining),
        )),
        Err(e) => checks.push(fail("relay tls", e.to_string())),
    }

    // Strongest check: a real authenticated Hello round-trip.
    if let Some(token) = token {
        match login::verify(&cfg.relay, &token, &trust).await {
            Ok(v) => checks.push(pass(
                "auth",
                format!("accepted (session {}, proto {})", v.session_id, v.proto),
            )),
            Err(e) => checks.push(fail("auth", e.to_string())),
        }
    }

    println!("\nEtherTunnel client doctor — {}\n", cfg.relay);
    for c in &checks {
        c.print();
    }
    let failed = checks.iter().filter(|c| !c.ok).count();
    if failed == 0 {
        println!("\nAll checks passed.");
        true
    } else {
        println!("\n{failed} check(s) failed.");
        false
    }
}
