mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use support::{start_enforcing_mock, Server};

/// The Phase 1 gate: 100 concurrent clients hammer the proxy while a mock upstream
/// strictly enforces the per-key rate window. If pacing is correct, every request
/// succeeds and the upstream records zero violations. Ignored by default (it takes
/// ~10s); run with `cargo test --test load -- --ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load test — run with `cargo test --test load -- --ignored`"]
async fn hundred_clients_zero_upstream_rate_violations() {
    let rpm = 40;
    // Mock enforces 40 req / 1s per key; the proxy runs with a 1s provider window
    // (+1s jitter margin), so it stays comfortably under that limit.
    let mock = start_enforcing_mock(rpm, Duration::from_millis(1000)).await;
    let s = Server::start_with_env(&[("SLUICE_PROVIDER_WINDOW_MS", "1000")]).await;
    let key = s
        .complete_wizard_get_key(
            "admin",
            "password123",
            "mock",
            &mock.base_url,
            "provider-key",
        )
        .await;

    let clients = 100usize;
    let per_client = 2usize;
    let mut handles = Vec::new();
    for _ in 0..clients {
        let base = s.base_url.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            for _ in 0..per_client {
                let r = client
                    .post(format!("{base}/v1/chat/completions"))
                    .header("authorization", format!("Bearer {key}"))
                    .body("{}")
                    .send()
                    .await
                    .expect("request send");
                assert!(r.status().is_success(), "a client saw {}", r.status());
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(
        mock.total.load(Ordering::Relaxed),
        clients * per_client,
        "not every request reached the upstream"
    );
    assert_eq!(
        mock.violations.load(Ordering::Relaxed),
        0,
        "upstream observed rate-limit violations — pacing is broken"
    );
}
