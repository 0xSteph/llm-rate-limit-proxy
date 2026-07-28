mod support;

use std::time::Duration;

use support::Server;

#[tokio::test]
async fn health_is_public_and_ok() {
    let s = Server::start().await;
    assert_eq!(s.get("/health").await.status(), 200);
}

#[tokio::test]
async fn security_headers_present_on_all_responses() {
    let s = Server::start().await;
    let r = s.get("/").await;
    let h = r.headers();
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert!(h.contains_key("content-security-policy"));
}

// --- Setup wizard + fail-closed gate ----------------------------------------

#[tokio::test]
async fn fresh_boot_is_setup_gated() {
    let s = Server::start().await;
    assert_eq!(s.get("/v1/models").await.status(), 503);
    let r = s.get("/").await;
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["location"], "/setup");
}

#[tokio::test]
async fn wizard_claims_proxy_and_opens_v1() {
    let s = Server::start().await;
    let r = s
        .complete_wizard("admin", "password123", "nim", "http://mock.test", "nvapi-x")
        .await;
    assert!(r.status().is_success(), "setup returned {}", r.status());
    // No longer setup-gated: keyed mode now answers 401 (missing key), not 503.
    assert_eq!(s.get("/v1/models").await.status(), 401);
}

#[tokio::test]
async fn second_setup_attempt_is_rejected() {
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "nim", "http://mock.test", "nvapi-x")
        .await;
    let r = s
        .complete_wizard("evil", "hax", "p", "http://mock.test", "k")
        .await;
    assert_eq!(r.status(), 409);
}

// --- Login / logout / throttle ----------------------------------------------

#[tokio::test]
async fn protected_route_redirects_to_login_after_setup() {
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "nim", "http://mock.test", "nvapi-x")
        .await;
    let r = s.get_anon("/").await;
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["location"], "/login");
}

#[tokio::test]
async fn login_grants_access_and_logout_revokes() {
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "nim", "http://mock.test", "nvapi-x")
        .await;

    let r = s.login("admin", "password123").await;
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["location"], "/");

    assert_eq!(s.get("/").await.status(), 200);

    s.logout().await;
    let r = s.get("/").await;
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["location"], "/login");
}

#[tokio::test]
async fn repeated_bad_logins_get_throttled() {
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "nim", "http://mock.test", "nvapi-x")
        .await;
    for _ in 0..5 {
        assert_eq!(s.login("admin", "wrong").await.status(), 401);
    }
    assert_eq!(s.login("admin", "wrong").await.status(), 429);
}

// --- Proxy pass-through ------------------------------------------------------

#[tokio::test]
async fn proxies_keyed_request_through_to_provider() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    let key = s
        .complete_wizard_get_key("admin", "password123", "mock", &mock, "provider-key")
        .await;

    let r = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(r#"{"model":"x","messages":[]}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(r.status(), 200);
    let text = r.text().await.unwrap();
    assert!(text.contains("\"mock\":\"ok\""), "proxied body was: {text}");
}

#[tokio::test]
async fn proxy_rejects_missing_key() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "mock", &mock, "provider-key")
        .await;
    let r = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn fails_over_from_bad_key_to_good_key() {
    use sluice::auth::{hash_password, new_client_key};
    use sluice::config::{Provider, ProviderKey, Role, StoredConfig, User, STORE_VERSION};

    let mock = support::start_failover_mock("bad-key").await;
    let (client_secret, client_rec) = new_client_key("test", "admin");
    let store = StoredConfig {
        version: STORE_VERSION,
        users: vec![User {
            username: "admin".into(),
            pw_hash: hash_password("password123"),
            role: Role::Superuser,
        }],
        providers: vec![Provider {
            name: "mock".into(),
            base_url: mock.clone(),
            keys: vec![
                ProviderKey {
                    key: "bad-key".into(),
                    enabled: true,
                    rpm: 40,
                    owner: "admin".into(),
                },
                ProviderKey {
                    key: "good-key".into(),
                    enabled: true,
                    rpm: 40,
                    owner: "admin".into(),
                },
            ],
        }],
        clients: vec![client_rec],
        aliases: vec![],
        settings: Default::default(),
    };
    let s = Server::start_seeded(&store, &[]).await;

    // First lane (bad-key) 429s; the proxy must fail over to good-key and return 200.
    let r = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {client_secret}"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.text().await.unwrap().contains("\"mock\":\"ok\""));
}

async fn served_by(s: &Server, secret: &str, body: String) -> String {
    let r = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {secret}"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let v: serde_json::Value = r.json().await.unwrap();
    v["served_by"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn a_conversation_keeps_one_key_as_its_transcript_grows() {
    use sluice::auth::{hash_password, new_client_key};
    use sluice::config::{Provider, ProviderKey, Role, StoredConfig, User, STORE_VERSION};

    let mock = support::start_key_reporting_mock().await;
    let (client_secret, client_rec) = new_client_key("test", "admin");
    let store = StoredConfig {
        version: STORE_VERSION,
        users: vec![User {
            username: "admin".into(),
            pw_hash: hash_password("password123"),
            role: Role::Superuser,
        }],
        providers: vec![Provider {
            name: "mock".into(),
            base_url: mock.clone(),
            keys: (0..4)
                .map(|i| ProviderKey {
                    key: format!("key-{i}"),
                    enabled: true,
                    rpm: 40,
                    owner: "admin".into(),
                })
                .collect(),
        }],
        clients: vec![client_rec],
        aliases: vec![],
        settings: Default::default(),
    };
    let s = Server::start_seeded(&store, &[]).await;

    // The opening messages are byte-identical every turn; only the tail grows.
    let opening =
        r#"{"role":"system","content":"you are a bot"},{"role":"user","content":"hello"}"#;
    let first = served_by(
        &s,
        &client_secret,
        format!(r#"{{"model":"m","messages":[{opening}]}}"#),
    )
    .await;
    let later = served_by(
        &s,
        &client_secret,
        format!(
            r#"{{"model":"m","messages":[{opening},{{"role":"assistant","content":"hi"}},{{"role":"user","content":"more"}}]}}"#
        ),
    )
    .await;

    assert_eq!(
        first, later,
        "a conversation must keep its key across turns to hold the prefix cache"
    );
}

#[tokio::test]
async fn a_rate_limited_key_is_benched_so_the_next_request_skips_it() {
    use sluice::auth::{hash_password, new_client_key};
    use sluice::config::{Provider, ProviderKey, Role, StoredConfig, User, STORE_VERSION};
    use std::sync::atomic::Ordering;

    let (mock, sick_hits) = support::start_benching_mock("sick-key").await;
    let (client_secret, client_rec) = new_client_key("test", "admin");
    let store = StoredConfig {
        version: STORE_VERSION,
        users: vec![User {
            username: "admin".into(),
            pw_hash: hash_password("password123"),
            role: Role::Superuser,
        }],
        providers: vec![Provider {
            name: "mock".into(),
            base_url: mock.clone(),
            keys: ["sick-key", "healthy-key"]
                .iter()
                .map(|k| ProviderKey {
                    key: (*k).into(),
                    enabled: true,
                    rpm: 40,
                    owner: "admin".into(),
                })
                .collect(),
        }],
        clients: vec![client_rec],
        aliases: vec![],
        settings: Default::default(),
    };
    let s = Server::start_seeded(&store, &[]).await;

    // No `messages`, so there is no session affinity: both requests fall to the
    // least-loaded lane and tie-break onto the sick key unless it gets benched.
    for _ in 0..2 {
        let r = s
            .client
            .post(format!("{}/v1/chat/completions", s.base_url))
            .header("authorization", format!("Bearer {client_secret}"))
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }

    assert_eq!(
        sick_hits.load(Ordering::Relaxed),
        1,
        "the rebuff must be remembered pool-wide, not rediscovered every request"
    );
}

#[tokio::test]
async fn deadline_exceeded_returns_504() {
    let mock = support::start_slow_mock(Duration::from_secs(3)).await;
    let s = Server::start().await;
    let key = s
        .complete_wizard_get_key("admin", "password123", "mock", &mock, "provider-key")
        .await;

    let r = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {key}"))
        .header("x-sluice-deadline-ms", "150")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 504);
}

#[tokio::test]
async fn streaming_request_gets_heartbeat_and_body() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    let key = s
        .complete_wizard_get_key("admin", "password123", "mock", &mock, "provider-key")
        .await;

    let r = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(r#"{"model":"x","stream":true,"messages":[]}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "text/event-stream");
    let body = r.text().await.unwrap();
    assert!(
        body.contains(": heartbeat"),
        "no heartbeat in stream: {body}"
    );
    assert!(body.contains("mock"), "no upstream body in stream: {body}");
}

#[tokio::test]
async fn virtual_model_falls_back_across_providers() {
    use sluice::auth::{hash_password, new_client_key};
    use sluice::config::{
        Alias, AliasTarget, Provider, ProviderKey, Role, StoredConfig, User, STORE_VERSION,
    };

    let mock_a = support::start_failover_mock("pa-key").await; // 429s provider A's key
    let mock_b = support::start_echo_mock().await; // provider B echoes the body
    let (secret, client_rec) = new_client_key("test", "admin");

    let store = StoredConfig {
        version: STORE_VERSION,
        users: vec![User {
            username: "admin".into(),
            pw_hash: hash_password("pw"),
            role: Role::Superuser,
        }],
        providers: vec![
            Provider {
                name: "pa".into(),
                base_url: mock_a,
                keys: vec![ProviderKey {
                    key: "pa-key".into(),
                    enabled: true,
                    rpm: 40,
                    owner: "admin".into(),
                }],
            },
            Provider {
                name: "pb".into(),
                base_url: mock_b,
                keys: vec![ProviderKey {
                    key: "pb-key".into(),
                    enabled: true,
                    rpm: 40,
                    owner: "admin".into(),
                }],
            },
        ],
        clients: vec![client_rec],
        aliases: vec![Alias {
            name: "smart".into(),
            targets: vec![
                AliasTarget {
                    provider: "pa".into(),
                    model: "model-x".into(),
                },
                AliasTarget {
                    provider: "pb".into(),
                    model: "model-y".into(),
                },
            ],
        }],
        settings: Default::default(),
    };
    let s = Server::start_seeded(&store, &[]).await;

    // `smart` resolves to [pa/model-x, pb/model-y]; pa 429s, so we fall over to pb,
    // which echoes back the rewritten model.
    let r = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {secret}"))
        .header("content-type", "application/json")
        .body(r#"{"model":"smart","messages":[]}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(r.status(), 200);
    let body = r.text().await.unwrap();
    assert!(
        body.contains("model-y"),
        "expected the fallback target's model in the echo: {body}"
    );
    assert!(
        !body.contains("smart"),
        "alias name leaked upstream: {body}"
    );
}

#[tokio::test]
async fn metrics_records_proxied_requests() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    let key = s
        .complete_wizard_get_key("admin", "password123", "mock", &mock, "provider-key")
        .await;

    let r = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {key}"))
        .body(r#"{"model":"gpt-x","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // /metrics is on the operator surface — needs a session.
    s.login("admin", "password123").await;
    let m = s.get("/metrics").await;
    assert_eq!(m.status(), 200);
    let body = m.text().await.unwrap();
    assert!(body.contains("sluice_requests_total"), "no metric: {body}");
    assert!(
        body.contains(r#"model="gpt-x""#),
        "model not recorded: {body}"
    );
    assert!(
        body.contains(r#"status="200""#),
        "status not recorded: {body}"
    );
}

#[tokio::test]
async fn history_api_returns_json_array() {
    let s = Server::start().await;
    s.complete_wizard(
        "admin",
        "password123",
        "mock",
        "http://mock.test",
        "provider-key",
    )
    .await;
    s.login("admin", "password123").await;
    let r = s.get("/api/history").await;
    assert_eq!(r.status(), 200);
    let body = r.text().await.unwrap();
    assert!(
        body.trim_start().starts_with('['),
        "expected JSON array: {body}"
    );
}

#[tokio::test]
async fn dashboard_and_stats_served_after_login() {
    let s = Server::start().await;
    s.complete_wizard(
        "admin",
        "password123",
        "mock",
        "http://mock.test",
        "provider-key",
    )
    .await;
    s.login("admin", "password123").await;

    let d = s.get("/").await;
    assert_eq!(d.status(), 200);
    assert_eq!(d.headers()["content-type"], "text/html; charset=utf-8");
    let html = d.text().await.unwrap();
    assert!(html.contains("gateway console"), "not the dashboard");

    let st = s.get("/api/stats").await;
    assert_eq!(st.status(), 200);
    assert!(st.text().await.unwrap().contains("\"total\""));

    let c = s.get("/dash/config.json").await;
    assert_eq!(c.status(), 200);
    assert!(c.text().await.unwrap().contains("capacity_rpm"));
}
