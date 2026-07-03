//! Live smoke test of [`PolarHttpClient`] against a real Polar environment.
//!
//! Ignored by default (needs network + a real license key). Run explicitly:
//!
//! ```sh
//! ETUN_TEST_POLAR_API=https://sandbox-api.polar.sh \
//! ETUN_TEST_POLAR_ORG=<org uuid> \
//! ETUN_TEST_POLAR_KEY=<a currently-granted license key> \
//! cargo test -p ethertunnel-relay --test live_polar -- --ignored --nocapture
//! ```
//!
//! Proves the hyper-rustls client speaks to the real endpoint (TLS, paths,
//! response shape) — the things a mock can't cover.

use ethertunnel_relay::polar::{PolarBackend, PolarHttpClient, ValidateOutcome};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::test]
#[ignore = "live network test; needs ETUN_TEST_POLAR_{API,ORG,KEY}"]
async fn live_validate_granted_key_and_unknown_key() {
    let (Some(api), Some(org), Some(key)) = (
        env("ETUN_TEST_POLAR_API"),
        env("ETUN_TEST_POLAR_ORG"),
        env("ETUN_TEST_POLAR_KEY"),
    ) else {
        panic!("set ETUN_TEST_POLAR_API / ETUN_TEST_POLAR_ORG / ETUN_TEST_POLAR_KEY");
    };
    let client = PolarHttpClient::new(api, org);

    // A currently-granted key validates with a customer and a benefit.
    match client.validate(&key).await {
        ValidateOutcome::Granted {
            customer_id,
            benefit_id,
        } => {
            println!("granted: customer_id={customer_id} benefit_id={benefit_id}");
            assert!(!customer_id.is_empty());
            assert!(!benefit_id.is_empty());
        }
        other => panic!("expected Granted, got {other:?}"),
    }

    // A syntactically-plausible but unknown key is definitively NotLicensed
    // (Polar answers 404 for both invalid and revoked keys).
    match client
        .validate("ETUN-00000000-0000-0000-0000-000000000000")
        .await
    {
        ValidateOutcome::NotLicensed => {}
        other => panic!("expected NotLicensed for an unknown key, got {other:?}"),
    }
}
