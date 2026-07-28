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
async fn requests_past_the_concurrency_cap_are_shed_with_retry_after() {
    use sluice::auth::{hash_password, new_client_key};
    use sluice::config::{
        Provider, ProviderKey, Role, Settings, StoredConfig, User, STORE_VERSION,
    };

    let mock = support::start_slow_mock(Duration::from_secs(2)).await;
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
            keys: vec![ProviderKey {
                key: "k".into(),
                enabled: true,
                rpm: 40,
                owner: "admin".into(),
            }],
        }],
        clients: vec![client_rec],
        aliases: vec![],
        settings: Settings {
            max_inflight: 1,
            ..Default::default()
        },
    };
    let s = Server::start_seeded(&store, &[]).await;

    // The first request holds the only slot for ~2s against the slow upstream.
    let (c, url, secret) = (s.client.clone(), s.base_url.clone(), client_secret.clone());
    let held = tokio::spawn(async move {
        c.post(format!("{url}/v1/chat/completions"))
            .header("authorization", format!("Bearer {secret}"))
            .body("{}")
            .send()
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let shed = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {client_secret}"))
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(shed.status(), 503);
    assert_eq!(
        shed.headers()["retry-after"],
        "1",
        "a shed client needs to be told to back off, not left to hammer"
    );
    let body: serde_json::Value = shed.json().await.unwrap();
    assert_eq!(body["error"]["code"], "overloaded");

    held.await.unwrap();
}

#[tokio::test]
async fn pressure_on_a_model_is_detected_across_keys_and_reported() {
    use sluice::auth::{hash_password, new_client_key};
    use sluice::config::{Provider, ProviderKey, Role, StoredConfig, User, STORE_VERSION};

    // Every key is rebuffed, so failing over cannot help — the signature of a
    // model-scoped limit rather than a per-key one.
    let mock = support::start_pressured_mock().await;
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

    s.client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {client_secret}"))
        .header("content-type", "application/json")
        .body(r#"{"model":"squeezed","messages":[]}"#)
        .send()
        .await
        .unwrap();

    s.login("admin", "password123").await;
    let body: serde_json::Value = s.get("/api/pressure").await.json().await.unwrap();
    let pressured = body["pressured"].as_array().unwrap();

    assert_eq!(
        pressured.len(),
        1,
        "rebuffs across distinct keys should indict the model: {body}"
    );
    assert_eq!(pressured[0]["model"], "squeezed");
    assert!(pressured[0]["limit"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn the_catalog_is_cached_and_lists_aliases_alongside_real_models() {
    use sluice::auth::{hash_password, new_client_key};
    use sluice::config::{
        Alias, AliasTarget, Provider, ProviderKey, Role, StoredConfig, User, STORE_VERSION,
    };
    use std::sync::atomic::Ordering;

    let (mock, upstream_hits) = support::start_catalog_mock("real-model").await;
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
            keys: vec![ProviderKey {
                key: "k".into(),
                enabled: true,
                rpm: 40,
                owner: "admin".into(),
            }],
        }],
        clients: vec![client_rec],
        aliases: vec![Alias {
            name: "my-virtual-model".into(),
            targets: vec![AliasTarget {
                provider: "mock".into(),
                model: "real-model".into(),
            }],
        }],
        settings: Default::default(),
    };
    let s = Server::start_seeded(&store, &[]).await;

    let mut bodies = Vec::new();
    for _ in 0..3 {
        let r = s
            .client
            .get(format!("{}/v1/models", s.base_url))
            .header("authorization", format!("Bearer {client_secret}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        bodies.push(r.json::<serde_json::Value>().await.unwrap());
    }

    assert_eq!(
        upstream_hits.load(Ordering::Relaxed),
        1,
        "a harness polling its catalog must not spend rate budget every time"
    );

    let ids: Vec<&str> = bodies[0]["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"real-model"), "got {ids:?}");
    assert!(
        ids.contains(&"my-virtual-model"),
        "an alias a harness can route to must be listed: {ids:?}"
    );
}

async fn stream_once(s: &Server, key: &str, body: &'static str) -> String {
    let r = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    r.text().await.unwrap()
}

#[tokio::test]
async fn streaming_requests_ask_upstream_for_exact_token_counts() {
    let mock = support::start_echo_mock().await;
    let s = Server::start().await;
    let key = s
        .complete_wizard_get_key("admin", "password123", "mock", &mock, "provider-key")
        .await;

    let echoed = stream_once(&s, &key, r#"{"model":"m","stream":true,"messages":[]}"#).await;
    assert!(
        echoed.contains("include_usage"),
        "without this the stream reports no usage at all and tokens can only be \
         guessed from frame counts; upstream saw: {echoed}"
    );
}

#[tokio::test]
async fn a_clients_own_stream_options_reaches_upstream_unchanged() {
    let mock = support::start_echo_mock().await;
    let s = Server::start().await;
    let key = s
        .complete_wizard_get_key("admin", "password123", "mock", &mock, "provider-key")
        .await;

    let echoed = stream_once(
        &s,
        &key,
        r#"{"model":"m","stream":true,"messages":[],"stream_options":{"include_usage":false}}"#,
    )
    .await;
    assert!(
        echoed.contains("\"include_usage\":false"),
        "the client asked for no usage and meant it: {echoed}"
    );
}

#[tokio::test]
async fn a_model_rejecting_stream_options_still_gets_its_stream() {
    let mock = support::start_rejects_stream_options_mock().await;
    let s = Server::start().await;
    let key = s
        .complete_wizard_get_key("admin", "password123", "mock", &mock, "provider-key")
        .await;

    let out = stream_once(&s, &key, r#"{"model":"picky","stream":true,"messages":[]}"#).await;
    assert!(
        out.contains("\"mock\":\"ok\""),
        "a 400 we caused by adding stream_options must not become the client's \
         error — it should be retried without the field: {out}"
    );
}

// --- Runtime settings ---------------------------------------------------------

async fn settings_post(s: &Server, path: &str, body: serde_json::Value) -> reqwest::Response {
    s.client
        .post(format!("{}{path}", s.base_url))
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn capacity_rpm(s: &Server) -> u64 {
    let cfg: serde_json::Value = s.get("/dash/config.json").await.json().await.unwrap();
    cfg["capacity_rpm"].as_u64().unwrap()
}

#[tokio::test]
async fn a_client_key_minted_through_settings_authenticates_immediately() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "mock", &mock, "provider-key")
        .await;
    s.login("admin", "password123").await;

    let r = settings_post(
        &s,
        "/api/settings/clients",
        serde_json::json!({"action": "mint", "label": "laptop"}),
    )
    .await;
    assert_eq!(r.status(), 200);
    let minted = r.json::<serde_json::Value>().await.unwrap();
    let key = minted["key"].as_str().expect("a secret is returned once");

    let r = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {key}"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "onboarding a harness must not require a restart or a config file edit"
    );
}

#[tokio::test]
async fn adding_a_provider_key_raises_capacity_without_a_restart() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "mock", &mock, "provider-key")
        .await;
    s.login("admin", "password123").await;

    let before = capacity_rpm(&s).await;
    let r = settings_post(
        &s,
        "/api/settings/provider-keys",
        serde_json::json!({"action": "add", "provider": "mock", "key": "second-key", "rpm": 25}),
    )
    .await;
    assert_eq!(r.status(), 200);

    assert_eq!(
        capacity_rpm(&s).await,
        before + 25,
        "the live pool must pick up the new key"
    );
}

#[tokio::test]
async fn disabling_the_last_key_is_refused() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "mock", &mock, "provider-key")
        .await;
    s.login("admin", "password123").await;

    let r = settings_post(
        &s,
        "/api/settings/provider-keys",
        serde_json::json!({"action": "update", "provider": "mock", "index": 0, "enabled": false}),
    )
    .await;
    assert_eq!(
        r.status(),
        400,
        "one stray toggle must not silently take the data plane down"
    );
    assert!(
        capacity_rpm(&s).await > 0,
        "capacity is intact after the refusal"
    );
}

#[tokio::test]
async fn the_settings_view_never_returns_a_secret() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "mock", &mock, "provider-key")
        .await;
    s.login("admin", "password123").await;

    let body = s.get("/api/settings").await.text().await.unwrap();
    assert!(
        !body.contains("provider-key"),
        "a settings page that renders live credentials is one screenshot from \
         leaking them: {body}"
    );
    assert!(
        body.contains("last4"),
        "but it still identifies each key: {body}"
    );
}

/// Guards the gap that made this confusing in the first place: the endpoint
/// existing is not the same as an operator being able to see it. Someone staring
/// at 0% capacity while nothing gets through needs the console to say why.
#[tokio::test]
async fn the_console_reads_and_surfaces_model_pressure() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "mock", &mock, "provider-key")
        .await;
    s.login("admin", "password123").await;

    let html = s.get("/").await.text().await.unwrap();
    assert!(
        html.contains("/api/pressure"),
        "the console must actually fetch the pressure endpoint"
    );
    assert!(
        html.contains("pressure-banner"),
        "and surface it, not just hold it in a variable"
    );
}

/// The multi-provider case end to end: a model that lives on one provider, a
/// fallback on another, both behind one endpoint and one client key — all
/// configured while the proxy is running.
#[tokio::test]
async fn a_second_provider_and_a_fallback_alias_can_be_added_live() {
    let primary = support::start_mock_upstream().await;
    let secondary = support::start_echo_mock().await;
    let s = Server::start().await;
    let client_key = s
        .complete_wizard_get_key("admin", "password123", "main", &primary, "k1")
        .await;
    s.login("admin", "password123").await;

    // Deliberately pasted with the /v1 suffix every OpenAI-compatible client asks
    // for; it has to be normalized away or requests 404 later with no clue why.
    let r = settings_post(
        &s,
        "/api/settings/providers",
        serde_json::json!({
            "action": "add", "name": "backup",
            "base_url": format!("{secondary}/v1"), "key": "k2"
        }),
    )
    .await;
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());

    let r = settings_post(
        &s,
        "/api/settings/aliases",
        serde_json::json!({
            "action": "upsert", "name": "my-agent",
            "targets": [
                {"provider": "backup", "model": "model-b"},
                {"provider": "main", "model": "model-a"}
            ]
        }),
    )
    .await;
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());

    let view: serde_json::Value = s.get("/api/settings").await.json().await.unwrap();
    let backup = view["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "backup")
        .expect("the new provider is stored");
    assert!(
        !backup["base_url"].as_str().unwrap().ends_with("/v1"),
        "a pasted /v1 suffix must be normalized away: {backup}"
    );

    let catalog: serde_json::Value = s
        .client
        .get(format!("{}/v1/models", s.base_url))
        .header("authorization", format!("Bearer {client_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = catalog["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    assert!(
        ids.contains(&"my-agent"),
        "a harness can only route to a virtual model it can see: {ids:?}"
    );
}

#[tokio::test]
async fn an_alias_pointing_at_an_unknown_provider_is_refused() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "main", &mock, "k1")
        .await;
    s.login("admin", "password123").await;

    let r = settings_post(
        &s,
        "/api/settings/aliases",
        serde_json::json!({
            "action": "upsert", "name": "broken",
            "targets": [{"provider": "does-not-exist", "model": "m"}]
        }),
    )
    .await;
    assert_eq!(
        r.status(),
        400,
        "an unreachable target would surface much later as an opaque routing miss"
    );
}

#[tokio::test]
async fn removing_a_provider_prunes_aliases_that_pointed_at_it() {
    let primary = support::start_mock_upstream().await;
    let secondary = support::start_echo_mock().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "main", &primary, "k1")
        .await;
    s.login("admin", "password123").await;

    settings_post(
        &s,
        "/api/settings/providers",
        serde_json::json!({"action": "add", "name": "temp", "base_url": secondary, "key": "k2"}),
    )
    .await;
    settings_post(
        &s,
        "/api/settings/aliases",
        serde_json::json!({
            "action": "upsert", "name": "doomed",
            "targets": [{"provider": "temp", "model": "m"}]
        }),
    )
    .await;
    settings_post(
        &s,
        "/api/settings/providers",
        serde_json::json!({"action": "remove", "name": "temp"}),
    )
    .await;

    let view: serde_json::Value = s.get("/api/settings").await.json().await.unwrap();
    assert!(
        view["aliases"].as_array().unwrap().is_empty(),
        "an alias with no reachable target is a routing failure waiting to happen: {view}"
    );
}

#[tokio::test]
async fn an_added_user_can_log_in_and_the_superuser_cannot_be_deleted() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "main", &mock, "k1")
        .await;
    s.login("admin", "password123").await;

    let r = settings_post(
        &s,
        "/api/settings/users",
        serde_json::json!({"action": "add", "username": "friend", "password": "correcthorsebattery"}),
    )
    .await;
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());

    let r = settings_post(
        &s,
        "/api/settings/users",
        serde_json::json!({"action": "remove", "username": "admin"}),
    )
    .await;
    assert_eq!(
        r.status(),
        400,
        "deleting the superuser locks everyone out of a running proxy"
    );

    s.logout().await;
    assert_eq!(
        s.login("friend", "correcthorsebattery").await.status(),
        303,
        "a user added through settings must be able to sign in"
    );
}

#[tokio::test]
async fn a_short_password_is_refused() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "main", &mock, "k1")
        .await;
    s.login("admin", "password123").await;

    let r = settings_post(
        &s,
        "/api/settings/users",
        serde_json::json!({"action": "add", "username": "weak", "password": "short"}),
    )
    .await;
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn settings_are_closed_to_anonymous_callers() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "mock", &mock, "provider-key")
        .await;
    assert_eq!(s.get_anon("/api/settings").await.status(), 303);
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
