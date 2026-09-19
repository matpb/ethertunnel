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

/// Polar answers 429 to a burst of validates, and the relay treats that as
/// `Unavailable` — which denies a key it has never cached. Space the live calls
/// out so the test measures the cap logic and not the rate limiter.
async fn pace() {
    tokio::time::sleep(std::time::Duration::from_secs(20)).await;
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

/// The pooled-cap fix (MAX over a customer's keys) against REAL Polar, with a
/// real customer holding two granted keys on two benefits. Everything else is
/// mocked somewhere in the suite; only this exercises `PolarHttpClient` over
/// TLS inside the cap arithmetic. Run:
///
/// ```sh
/// ETUN_TEST_POLAR_API=https://sandbox-api.polar.sh \
/// ETUN_TEST_POLAR_ORG=<org uuid> \
/// ETUN_TEST_POLAR_KEY_BIG=<key on the larger benefit> \
/// ETUN_TEST_POLAR_KEY_SMALL=<key on the smaller benefit, SAME customer> \
/// cargo test -p ethertunnel-relay --test live_polar -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "live network test; needs ETUN_TEST_POLAR_{API,ORG,KEY_BIG,KEY_SMALL}"]
async fn live_pooled_cap_survives_a_small_sibling_key() {
    use ethertunnel_relay::polar::{CapDecision, LicenseCache, PolarGate, PolarPolicy, Reconciler};
    use ethertunnel_relay::registry::Registry;
    use ethertunnel_relay::router::Router;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    const BIG: i64 = 3;
    const SMALL: i64 = 1;
    const TTL: i64 = 300;
    const STALENESS: i64 = 259_200;
    const GRACE: i64 = 2_592_000;

    let (Some(api), Some(org), Some(key_big), Some(key_small)) = (
        env("ETUN_TEST_POLAR_API"),
        env("ETUN_TEST_POLAR_ORG"),
        env("ETUN_TEST_POLAR_KEY_BIG"),
        env("ETUN_TEST_POLAR_KEY_SMALL"),
    ) else {
        panic!("set ETUN_TEST_POLAR_{{API,ORG,KEY_BIG,KEY_SMALL}}");
    };

    // Learn the real customer/benefit pairing from Polar rather than hardcoding
    // it, then assert this fixture actually has the shape the bug needs.
    let probe = PolarHttpClient::new(api.clone(), org.clone());
    let mut ids = Vec::new();
    for key in [&key_big, &key_small] {
        pace().await;
        match probe.validate(key).await {
            ValidateOutcome::Granted {
                customer_id,
                benefit_id,
            } => ids.push((customer_id, benefit_id)),
            other => panic!("expected Granted, got {other:?}"),
        }
    }
    let (cust_big, ben_big) = ids[0].clone();
    let (cust_small, ben_small) = ids[1].clone();
    assert_eq!(
        cust_big, cust_small,
        "fixture must be two keys on ONE customer"
    );
    assert_ne!(ben_big, ben_small, "fixture must span two benefits");
    println!("customer={cust_big} big={ben_big}({BIG}) small={ben_small}({SMALL})");

    let dir = std::env::temp_dir().join(format!("etun-live-pooled-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cache_path = dir.join("polar-cache.db");

    let policy = PolarPolicy {
        organization_id: org.clone(),
        cache_ttl_secs: TTL,
        staleness_secs: STALENESS,
        cap_prune_grace_secs: GRACE,
        // Never consume a real activation slot: the fixture keys have very few.
        activate_on_claim: false,
        benefits: [(ben_big.clone(), BIG), (ben_small.clone(), SMALL)]
            .into_iter()
            .collect(),
        max_validate_per_sec: 10,
        validate_burst: 30,
    };
    let registry = Arc::new(Registry::open_in_memory("ethertunnel.com").unwrap());
    let router = Arc::new(Router::new());
    let gate = PolarGate::new(
        LicenseCache::open(&cache_path).unwrap(),
        policy,
        Box::new(PolarHttpClient::new(api.clone(), org.clone())),
    );
    gate.set_reconciler(Arc::new(Reconciler {
        registry: registry.clone(),
        router: router.clone(),
        domain: "ethertunnel.com".into(),
    }));

    // 1. The big key authenticates and fills its plan. Its probe result is
    //    still inside the cache TTL, so this costs no extra live call; the
    //    reconcile it skips would be a no-op on an empty pool anyway.
    seed_from_probe(&cache_path, &key_big, &cust_big, &ben_big, BIG);
    let user = gate.authenticate(&key_big).await.expect("big key granted");
    for label in ["live-a", "live-b", "live-c"] {
        assert!(registry.claim_label(user.user_id, label).unwrap());
    }
    assert_eq!(registry.count_owned_resources(user.user_id).unwrap(), BIG);
    assert_eq!(
        gate.cap_for(&user.name, ethertunnel_relay::polar::now_unix()),
        CapDecision::Cap(BIG)
    );

    // 2. The small sibling key revalidates (real HTTPS, first miss for its
    //    hash). Pre-fix this pruned the pool to 1 and deleted two labels.
    pace().await;
    let user2 = gate
        .authenticate(&key_small)
        .await
        .expect("small key granted");
    assert_eq!(user2.user_id, user.user_id, "one customer, one account");
    assert_eq!(
        registry.count_owned_resources(user.user_id).unwrap(),
        BIG,
        "the {SMALL}-tunnel key must not evict what the {BIG}-tunnel key pays for"
    );
    let mut owned = registry.owned_hostnames(user.user_id).unwrap();
    owned.sort();
    assert_eq!(
        owned,
        vec![
            "live-a.ethertunnel.com",
            "live-b.ethertunnel.com",
            "live-c.ethertunnel.com"
        ]
    );
    assert_eq!(
        gate.cap_for(&user.name, ethertunnel_relay::polar::now_unix()),
        CapDecision::Cap(BIG),
        "the claim gate reports the pooled cap, not the presenting key's"
    );

    // 3. Negative control — a GENUINE downgrade still prunes. Age the big key
    //    past the destructive grace and the small one past its cache TTL, so
    //    the next small-key revalidation is the real thing.
    let now = ethertunnel_relay::polar::now_unix();
    let side = LicenseCache::open(&cache_path).unwrap();
    for (key, at) in [(&key_big, now - GRACE - 1), (&key_small, now - TTL - 1)] {
        let hash = Sha256::digest(key.as_bytes()).to_vec();
        let mut row = side
            .get(&hash)
            .unwrap()
            .expect("row cached by authenticate");
        row.validated_at = at;
        side.upsert(&row).unwrap();
    }
    pace().await;
    gate.authenticate(&key_small)
        .await
        .expect("small key still granted");
    assert_eq!(
        registry.count_owned_resources(user.user_id).unwrap(),
        SMALL,
        "an abandoned big key stops backing the pool once it ages out"
    );
    assert_eq!(
        registry.owned_hostnames(user.user_id).unwrap(),
        vec!["live-a.ethertunnel.com"],
        "the prune grandfathers the oldest"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Write a probe's validate result straight into the cache, so a key the test
/// has already validated does not spend a second live call on the same answer.
fn seed_from_probe(
    cache_path: &std::path::Path,
    key: &str,
    customer_id: &str,
    benefit_id: &str,
    cap: i64,
) {
    use ethertunnel_relay::polar::{LicenseCache, LicenseRow};
    use sha2::{Digest, Sha256};
    LicenseCache::open(cache_path)
        .unwrap()
        .upsert(&LicenseRow {
            key_hash: Sha256::digest(key.as_bytes()).to_vec(),
            customer_id: customer_id.to_owned(),
            benefit_id: benefit_id.to_owned(),
            max_tunnels: Some(cap),
            status: "granted".into(),
            activation_id: None,
            validated_at: ethertunnel_relay::polar::now_unix(),
        })
        .unwrap();
}
