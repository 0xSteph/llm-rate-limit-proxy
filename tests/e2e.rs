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
    use llm_rate_limit_proxy::auth::{hash_password, new_client_key};
    use llm_rate_limit_proxy::config::{
        Provider, ProviderKey, Role, StoredConfig, User, STORE_VERSION,
    };

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
            protocol: Default::default(),
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
    use llm_rate_limit_proxy::auth::{hash_password, new_client_key};
    use llm_rate_limit_proxy::config::{
        Provider, ProviderKey, Role, StoredConfig, User, STORE_VERSION,
    };

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
            protocol: Default::default(),
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
    use llm_rate_limit_proxy::auth::{hash_password, new_client_key};
    use llm_rate_limit_proxy::config::{
        Provider, ProviderKey, Role, StoredConfig, User, STORE_VERSION,
    };
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
            protocol: Default::default(),
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
    use llm_rate_limit_proxy::auth::{hash_password, new_client_key};
    use llm_rate_limit_proxy::config::{
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
            protocol: Default::default(),
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
    use llm_rate_limit_proxy::auth::{hash_password, new_client_key};
    use llm_rate_limit_proxy::config::{
        Provider, ProviderKey, Role, StoredConfig, User, STORE_VERSION,
    };

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
            protocol: Default::default(),
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
    use llm_rate_limit_proxy::auth::{hash_password, new_client_key};
    use llm_rate_limit_proxy::config::{
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
            protocol: Default::default(),
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
        .header("x-llm-rate-limit-proxy-deadline-ms", "150")
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
    use llm_rate_limit_proxy::auth::{hash_password, new_client_key};
    use llm_rate_limit_proxy::config::{
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
                protocol: Default::default(),
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
                protocol: Default::default(),
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
    assert!(
        body.contains("llm_rate_limit_proxy_requests_total"),
        "no metric: {body}"
    );
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
    // Anchor on structure the script actually binds to, not on display copy —
    // a restyle should not be able to fail this, but removing the tab shell or
    // the status strip should.
    assert!(html.contains("id=\"tabs\""), "no tab shell: {html:.200}");
    assert!(html.contains("id=\"strip\""), "no status strip");
    assert!(
        html.contains("/api/stats"),
        "console does not read the stats API"
    );

    let st = s.get("/api/stats").await;
    assert_eq!(st.status(), 200);
    assert!(st.text().await.unwrap().contains("\"total\""));

    let c = s.get("/dash/config.json").await;
    assert_eq!(c.status(), 200);
    assert!(c.text().await.unwrap().contains("capacity_rpm"));
}

// --- Authorization: session is not the same as permission ---------------------

/// Seed a proxy with an admin and a plain user, returning the server.
async fn server_with_plain_user(mock: &str) -> Server {
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "main", mock, "k1")
        .await;
    s.login("admin", "password123").await;
    settings_post(
        &s,
        "/api/settings/users",
        serde_json::json!({"action": "add", "username": "plain", "password": "correcthorsebattery"}),
    )
    .await;
    s.logout().await;
    s
}

/// A logged-in account is not an administrator. Without this the weakest
/// password on the box is a route to every provider key the pool holds.
#[tokio::test]
async fn a_plain_user_cannot_change_server_configuration() {
    let mock = support::start_mock_upstream().await;
    let s = server_with_plain_user(&mock).await;
    assert_eq!(s.login("plain", "correcthorsebattery").await.status(), 303);

    for (path, body) in [
        (
            "/api/settings/provider-keys",
            serde_json::json!({"action": "add", "provider": "main", "key": "stolen", "rpm": 40}),
        ),
        (
            "/api/settings/providers",
            serde_json::json!({"action": "remove", "name": "main"}),
        ),
        (
            "/api/settings/limits",
            serde_json::json!({"max_inflight": 1}),
        ),
        (
            "/api/settings/users",
            serde_json::json!({"action": "add", "username": "mine", "password": "correcthorsebattery"}),
        ),
    ] {
        let r = settings_post(&s, path, body).await;
        assert_eq!(r.status(), 403, "{path} was not admin-guarded");
    }
}

/// The shared-pool case still has to work: someone who contributes a key gets
/// their own client credential without being handed the whole server.
#[tokio::test]
async fn a_plain_user_may_still_mint_their_own_client_key() {
    let mock = support::start_mock_upstream().await;
    let s = server_with_plain_user(&mock).await;
    s.login("plain", "correcthorsebattery").await;

    let r = settings_post(
        &s,
        "/api/settings/clients",
        serde_json::json!({"action": "mint", "label": "laptop"}),
    )
    .await;
    assert_eq!(r.status(), 200);
    let key = r.json::<serde_json::Value>().await.unwrap()["key"]
        .as_str()
        .unwrap()
        .to_string();

    let used = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {key}"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(used.status(), 200, "their own key must work");
}

/// One user must not be able to revoke another's credential.
#[tokio::test]
async fn a_plain_user_cannot_revoke_someone_elses_client_key() {
    let mock = support::start_mock_upstream().await;
    let s = server_with_plain_user(&mock).await;

    s.login("admin", "password123").await;
    let minted = settings_post(
        &s,
        "/api/settings/clients",
        serde_json::json!({"action": "mint", "label": "admins-own"}),
    )
    .await
    .json::<serde_json::Value>()
    .await
    .unwrap();
    let victim_last4 =
        minted["key"].as_str().unwrap()[minted["key"].as_str().unwrap().len() - 4..].to_string();
    s.logout().await;

    s.login("plain", "correcthorsebattery").await;
    let r = settings_post(
        &s,
        "/api/settings/clients",
        serde_json::json!({"action": "revoke", "last4": victim_last4}),
    )
    .await;
    assert_eq!(
        r.status(),
        403,
        "revoking another user's key must be refused"
    );
}

/// Resetting a password is the standard response to a compromised account. If
/// existing sessions survive it, the reset achieves nothing against whoever is
/// already holding a cookie.
#[tokio::test]
async fn changing_a_password_invalidates_that_users_existing_sessions() {
    let mock = support::start_mock_upstream().await;
    let s = server_with_plain_user(&mock).await;

    // A second client, so the victim's cookie jar is independent of the admin's.
    let victim = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let login = victim
        .post(format!("{}/login", s.base_url))
        .form(&[("username", "plain"), ("password", "correcthorsebattery")])
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 303);
    let before = victim
        .get(format!("{}/api/settings", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(before.status(), 200, "session works before the reset");

    // An admin resets that account's password.
    s.login("admin", "password123").await;
    let r = settings_post(
        &s,
        "/api/settings/users",
        serde_json::json!({"action": "set_password", "username": "plain",
                           "password": "a-completely-new-one"}),
    )
    .await;
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());

    let after = victim
        .get(format!("{}/api/settings", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        303,
        "a reset password must not leave the old session usable"
    );
}

/// The settings API existing is not the same as an operator being able to use
/// it. Every route needs a control, or configuration stays a curl command.
#[tokio::test]
async fn the_console_exposes_a_control_for_every_settings_route() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "main", &mock, "k1")
        .await;
    s.login("admin", "password123").await;

    let html = s.get("/").await.text().await.unwrap();
    for route in [
        "/api/settings/providers",
        "/api/settings/provider-keys",
        "/api/settings/clients",
        "/api/settings/aliases",
        "/api/settings/users",
        "/api/settings/limits",
    ] {
        assert!(html.contains(route), "no control posts to {route}");
    }
    assert!(html.contains(r#"data-tab="settings""#), "no settings tab");
}

/// The doubled-prefix tolerance has to apply to every route, not just the ones
/// that get forwarded. A harness misconfigured this way asks for its catalog
/// down the same wrong path as everything else.
#[tokio::test]
async fn a_doubled_prefix_still_reaches_the_local_catalog() {
    let (mock, upstream_hits) = support::start_catalog_mock("real-model").await;
    let s = Server::start().await;
    let key = s
        .complete_wizard_get_key("admin", "password123", "mock", &mock, "k1")
        .await;

    // Warm the catalog through the correct path (one upstream fetch).
    let ok = s
        .client
        .get(format!("{}/v1/models", s.base_url))
        .header("authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // Now the misconfigured path. It must be answered locally, from cache.
    let doubled = s
        .client
        .get(format!("{}/v1/v1/models", s.base_url))
        .header("authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(doubled.status(), 200);
    let ids: Vec<String> = doubled.json::<serde_json::Value>().await.unwrap()["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&"real-model".to_string()), "got {ids:?}");
    assert_eq!(
        upstream_hits.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the doubled path was forwarded upstream instead of served from cache"
    );
}

// --- Scrapeable metrics -------------------------------------------------------

/// A metrics endpoint only a browser can read is not a metrics endpoint. It has
/// to answer a scraper carrying credentials, with a status rather than a login
/// page — Prometheus cannot follow a redirect into HTML and report anything.
#[tokio::test]
async fn prometheus_can_scrape_metrics_with_credentials() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "main", &mock, "k1")
        .await;

    let anon = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let bare = anon
        .get(format!("{}/metrics", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        bare.status(),
        401,
        "a scraper needs a status, not a redirect"
    );

    let good = anon
        .get(format!("{}/metrics", s.base_url))
        .basic_auth("admin", Some("password123"))
        .send()
        .await
        .unwrap();
    assert_eq!(good.status(), 200);
    assert!(good
        .text()
        .await
        .unwrap()
        .contains("llm_rate_limit_proxy_requests_total"));

    let wrong = anon
        .get(format!("{}/metrics", s.base_url))
        .basic_auth("admin", Some("nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);

    let no_such_user = anon
        .get(format!("{}/metrics", s.base_url))
        .basic_auth("ghost", Some("password123"))
        .send()
        .await
        .unwrap();
    assert_eq!(no_such_user.status(), 401);
}

/// A logged-in operator should still be able to eyeball it in a browser.
#[tokio::test]
async fn a_session_still_reaches_metrics() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "main", &mock, "k1")
        .await;
    s.login("admin", "password123").await;
    assert_eq!(s.get("/metrics").await.status(), 200);
}

/// Metrics that exist but are never recorded are the same as no metrics. This
/// drives a real request through and asserts the new measurements actually
/// arrive at both surfaces — the failure mode being a field that compiles,
/// exposes, and is forever zero.
#[tokio::test]
async fn the_new_measurements_are_actually_recorded() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    let key = s
        .complete_wizard_get_key("admin", "password123", "mock", &mock, "k1")
        .await;

    s.client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(
            r#"{"model":"m","max_tokens":256,"temperature":0.2,
                "messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"yo"}],
                "tools":[{"type":"function"}]}"#,
        )
        .send()
        .await
        .unwrap();

    s.login("admin", "password123").await;
    let stats: serde_json::Value = s.get("/api/stats").await.json().await.unwrap();

    let shape = &stats["shape"][0];
    assert_eq!(shape["avg_messages"], 2, "conversation depth: {stats}");
    assert_eq!(shape["avg_tools"], 1, "tools offered: {stats}");
    assert_eq!(shape["avg_max_tokens"], 256, "output budget: {stats}");
    assert_eq!(shape["avg_temperature_x100"], 20, "sampling: {stats}");
    assert_eq!(stats["buffered"], 1, "stream mix: {stats}");
    assert!(
        stats["queue_wait"]["count"].as_u64().unwrap() >= 1,
        "queue wait never recorded: {stats}"
    );

    // A request that has finished must not still be counted as in flight.
    assert_eq!(stats["active"], 0, "the in-flight gauge leaked: {stats}");

    let prom = s.get("/metrics").await.text().await.unwrap();
    for family in [
        "llm_rate_limit_proxy_ttft_ms",
        "llm_rate_limit_proxy_tokens_per_second",
        "llm_rate_limit_proxy_queue_wait_ms",
        "llm_rate_limit_proxy_finish_reason_total",
        "llm_rate_limit_proxy_request_shape",
        "llm_rate_limit_proxy_events_total",
        "llm_rate_limit_proxy_stream_requests_total",
        "llm_rate_limit_proxy_active_requests",
    ] {
        assert!(prom.contains(family), "{family} missing from /metrics");
    }
}

/// An unauthorized attempt should be countable — it is the signal that someone
/// is probing, and it was previously invisible.
#[tokio::test]
async fn refusals_are_counted() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "mock", &mock, "k1")
        .await;

    for _ in 0..3 {
        s.client
            .post(format!("{}/v1/chat/completions", s.base_url))
            .header("authorization", "Bearer lrlp_wrong")
            .body("{}")
            .send()
            .await
            .unwrap();
    }

    s.login("admin", "password123").await;
    let stats: serde_json::Value = s.get("/api/stats").await.json().await.unwrap();
    let unauthorized = stats["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "unauthorized")
        .map(|e| e["count"].as_u64().unwrap())
        .unwrap_or(0);
    assert_eq!(unauthorized, 3, "refusals not counted: {stats}");
}

/// The allowlist has to actually refuse, and has to refuse before anything
/// expensive happens — but must never lock out the machine it runs on.
#[tokio::test]
async fn a_source_allowlist_refuses_everyone_else_but_never_loopback() {
    use llm_rate_limit_proxy::auth::{hash_password, new_client_key};
    use llm_rate_limit_proxy::config::{
        Provider, ProviderKey, Role, Settings, StoredConfig, User, STORE_VERSION,
    };

    let mock = support::start_mock_upstream().await;
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
            protocol: Default::default(),
            keys: vec![ProviderKey {
                key: "k".into(),
                enabled: true,
                rpm: 40,
                owner: "admin".into(),
            }],
        }],
        clients: vec![client_rec],
        aliases: vec![],
        // Admits one address on a network this test is not on. Every request
        // here arrives from loopback, which must still be allowed.
        settings: Settings {
            allow_from: vec!["192.168.1.239".into()],
            ..Default::default()
        },
    };
    let s = Server::start_seeded(&store, &[]).await;

    // The tests reach it over loopback, which is exempt by design.
    assert_eq!(s.get("/health").await.status(), 200);
    let r = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {client_secret}"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "loopback must never be locked out by an allowlist"
    );
}

/// A rule that admits nothing must still leave /health answerable, or the
/// supervisor kills a proxy that is working.
#[tokio::test]
async fn health_stays_reachable_regardless_of_the_allowlist() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "mock", &mock, "k1")
        .await;
    s.login("admin", "password123").await;
    let r = settings_post(
        &s,
        "/api/settings/limits",
        serde_json::json!({"max_inflight": 512}),
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(s.get("/health").await.status(), 200);
}

/// A rule that cannot be parsed must be refused, not dropped. Silently
/// discarding one leaves the operator believing they are filtered when they are
/// not — the worst possible outcome for a security control.
#[tokio::test]
async fn an_unparseable_allow_rule_is_refused() {
    let mock = support::start_mock_upstream().await;
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "mock", &mock, "k1")
        .await;
    s.login("admin", "password123").await;

    let bad = settings_post(
        &s,
        "/api/settings/limits",
        serde_json::json!({"allow_from": ["192.168.1.239", "not-an-address"]}),
    )
    .await;
    assert_eq!(bad.status(), 400);

    let good = settings_post(
        &s,
        "/api/settings/limits",
        serde_json::json!({"allow_from": ["192.168.1.239", "100.64.0.0/10"]}),
    )
    .await;
    assert_eq!(good.status(), 200);

    let view: serde_json::Value = s.get("/api/settings").await.json().await.unwrap();
    assert_eq!(
        view["settings"]["allow_from"],
        serde_json::json!(["192.168.1.239", "100.64.0.0/10"]),
        "the good list must have been stored, and the bad one must not"
    );
}

// --- Anthropic protocol ------------------------------------------------------

/// Seed a store with one Anthropic provider and one OpenAI provider, and return
/// the client secret alongside the server.
async fn anthropic_and_openai(anthropic_url: &str, openai_url: &str) -> (Server, String) {
    use llm_rate_limit_proxy::auth::{hash_password, new_client_key};
    use llm_rate_limit_proxy::config::{
        Protocol, Provider, ProviderKey, Role, StoredConfig, User, STORE_VERSION,
    };

    let (client_secret, client_rec) = new_client_key("test", "admin");
    let key = |k: &str| ProviderKey {
        key: k.into(),
        enabled: true,
        rpm: 40,
        owner: "admin".into(),
    };
    let store = StoredConfig {
        version: STORE_VERSION,
        users: vec![User {
            username: "admin".into(),
            pw_hash: hash_password("password123"),
            role: Role::Superuser,
        }],
        // OpenAI deliberately first. Lanes are chosen least-loaded with ties
        // broken to the lower index, so on an idle pool lane 0 wins — which
        // means an Anthropic request landing correctly proves the protocol
        // filter did it, not the load balancer.
        providers: vec![
            Provider {
                name: "openai".into(),
                base_url: openai_url.to_string(),
                protocol: Protocol::OpenAi,
                keys: vec![key("sk-openai-secret")],
            },
            Provider {
                name: "anthropic".into(),
                base_url: anthropic_url.to_string(),
                protocol: Protocol::Anthropic,
                keys: vec![key("sk-ant-secret")],
            },
        ],
        clients: vec![client_rec],
        aliases: vec![],
        settings: Default::default(),
    };
    (Server::start_seeded(&store, &[]).await, client_secret)
}

/// Claude Code authenticates with `x-api-key`, not `Authorization: Bearer`.
/// Rejecting it was the single thing that kept every Anthropic-native client out.
#[tokio::test]
async fn an_anthropic_client_authenticates_with_x_api_key() {
    let anthropic = support::start_anthropic_mock().await;
    let openai = support::start_mock_upstream().await;
    let (s, secret) = anthropic_and_openai(&anthropic, &openai).await;

    let r = s
        .client
        .post(format!("{}/v1/messages", s.base_url))
        .header("x-api-key", &secret)
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-test","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "x-api-key was not accepted as client auth");

    let wrong = s
        .client
        .post(format!("{}/v1/messages", s.base_url))
        .header("x-api-key", "not-a-real-key")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401, "a bad x-api-key must still be refused");
}

/// Upstream auth follows the provider's protocol, and the client's own credential
/// never travels with the request — the proxy holds the real keys precisely so
/// the client never has to.
#[tokio::test]
async fn an_anthropic_upstream_gets_x_api_key_and_a_version_not_bearer() {
    let anthropic = support::start_anthropic_mock().await;
    let openai = support::start_mock_upstream().await;
    let (s, secret) = anthropic_and_openai(&anthropic, &openai).await;

    let body: serde_json::Value = s
        .client
        .post(format!("{}/v1/messages", s.base_url))
        .header("x-api-key", &secret)
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-test","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(
        body["saw_x_api_key"], "sk-ant-secret",
        "upstream should be presented the provider key via x-api-key"
    );
    assert_eq!(
        body["saw_authorization"], "",
        "an Anthropic upstream must not be sent a Bearer header"
    );
    assert_eq!(
        body["saw_anthropic_version"], "2023-06-01",
        "anthropic-version is required on every request"
    );
    assert_ne!(
        body["saw_x_api_key"],
        serde_json::json!(secret),
        "the client's own key must never be forwarded upstream"
    );
}

/// A client that pins its own API version keeps it: that header decides the
/// response shape it is prepared to parse.
#[tokio::test]
async fn a_clients_own_anthropic_version_is_left_alone() {
    let anthropic = support::start_anthropic_mock().await;
    let openai = support::start_mock_upstream().await;
    let (s, secret) = anthropic_and_openai(&anthropic, &openai).await;

    let body: serde_json::Value = s
        .client
        .post(format!("{}/v1/messages", s.base_url))
        .header("x-api-key", &secret)
        .header("anthropic-version", "2024-10-22")
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-test","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(body["saw_anthropic_version"], "2024-10-22");
}

/// The proxy forwards bodies rather than translating them, so a request can only
/// be served by a provider speaking its shape. Sending an Anthropic body to an
/// OpenAI upstream would earn a 400 no matter which key served it.
#[tokio::test]
async fn a_request_only_reaches_a_provider_speaking_its_protocol() {
    let anthropic = support::start_anthropic_mock().await;
    let openai = support::start_echo_mock().await;
    let (s, secret) = anthropic_and_openai(&anthropic, &openai).await;

    // Anthropic route -> the Anthropic mock, even though the OpenAI lane is
    // lane 0 and would otherwise win the tie on an idle pool.
    let a: serde_json::Value = s
        .client
        .post(format!("{}/v1/messages", s.base_url))
        .header("x-api-key", &secret)
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-test","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(a["type"], "message", "did not reach the Anthropic upstream");

    // OpenAI route -> the echo mock, which returns exactly what it was sent and
    // therefore carries none of the Anthropic mock's observation fields.
    let o: serde_json::Value = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {secret}"))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-x","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(o["model"], "gpt-x", "did not reach the OpenAI upstream");
    assert!(
        o.get("saw_x_api_key").is_none(),
        "an OpenAI request was served by the Anthropic lane"
    );
}

/// `stream_options` is an OpenAI field. Anthropic reports usage unasked and
/// rejects unknown top-level fields, so injecting it there turns a good request
/// into a 400.
#[tokio::test]
async fn stream_options_is_never_added_to_an_anthropic_body() {
    let anthropic = support::start_anthropic_mock().await;
    let openai = support::start_mock_upstream().await;
    let (s, secret) = anthropic_and_openai(&anthropic, &openai).await;

    let raw = s
        .client
        .post(format!("{}/v1/messages", s.base_url))
        .header("x-api-key", &secret)
        .header("content-type", "application/json")
        .body(
            r#"{"model":"claude-test","stream":true,"messages":[{"role":"user","content":"hi"}]}"#,
        )
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(
        !raw.contains("stream_options"),
        "stream_options was injected into an Anthropic request: {raw}"
    );
}

/// Anthropic names its token counts input/output rather than prompt/completion.
/// Read the wrong pair and every Anthropic request records as zero tokens.
#[tokio::test]
async fn anthropic_token_counts_are_recorded() {
    let anthropic = support::start_anthropic_mock().await;
    let openai = support::start_mock_upstream().await;
    let (s, secret) = anthropic_and_openai(&anthropic, &openai).await;

    s.client
        .post(format!("{}/v1/messages", s.base_url))
        .header("x-api-key", &secret)
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-test","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .unwrap();

    s.login("admin", "password123").await;
    let stats: serde_json::Value = s.get("/api/stats").await.json().await.unwrap();
    let row = stats["models"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["model"] == "claude-test")
        .expect("claude-test not in stats");
    assert_eq!(row["prompt_tokens"], 11, "input_tokens not recorded");
    assert_eq!(row["completion_tokens"], 7, "output_tokens not recorded");
}

/// With no provider speaking the client's protocol, the request must be refused
/// rather than forwarded to an upstream that cannot parse it. Misrouting would
/// surface as a confusing 400 from someone else's API.
#[tokio::test]
async fn an_anthropic_request_is_refused_when_no_anthropic_provider_exists() {
    use llm_rate_limit_proxy::auth::{hash_password, new_client_key};
    use llm_rate_limit_proxy::config::{
        Protocol, Provider, ProviderKey, Role, StoredConfig, User, STORE_VERSION,
    };

    let openai = support::start_echo_mock().await;
    let (client_secret, client_rec) = new_client_key("test", "admin");
    let store = StoredConfig {
        version: STORE_VERSION,
        users: vec![User {
            username: "admin".into(),
            pw_hash: hash_password("password123"),
            role: Role::Superuser,
        }],
        providers: vec![Provider {
            name: "openai".into(),
            base_url: openai.clone(),
            protocol: Protocol::OpenAi,
            keys: vec![ProviderKey {
                key: "sk-openai-secret".into(),
                enabled: true,
                rpm: 40,
                owner: "admin".into(),
            }],
        }],
        clients: vec![client_rec],
        aliases: vec![],
        settings: Default::default(),
    };
    let s = Server::start_seeded(&store, &[]).await;

    let r = s
        .client
        .post(format!("{}/v1/messages", s.base_url))
        .header("x-api-key", &client_secret)
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-test","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        503,
        "an Anthropic request was routed to an OpenAI-only pool"
    );

    // The same pool still serves OpenAI traffic normally.
    let ok = s
        .client
        .post(format!("{}/v1/chat/completions", s.base_url))
        .header("authorization", format!("Bearer {client_secret}"))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-x","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
}

/// Anthropic reports input tokens in `message_start` (nested under `message`) and
/// output tokens plus the stop reason in `message_delta` (nested under `delta`).
/// Reading only the top level of each frame records a stream's output and none of
/// its input, and loses truncation entirely.
#[tokio::test]
async fn a_streamed_anthropic_response_accounts_for_both_frames() {
    let anthropic = support::start_anthropic_stream_mock().await;
    let openai = support::start_mock_upstream().await;
    let (s, secret) = anthropic_and_openai(&anthropic, &openai).await;

    let body = s
        .client
        .post(format!("{}/v1/messages", s.base_url))
        .header("x-api-key", &secret)
        .header("content-type", "application/json")
        .body(
            r#"{"model":"claude-test","stream":true,"messages":[{"role":"user","content":"hi"}]}"#,
        )
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("message_stop"),
        "stream did not complete: {body}"
    );

    s.login("admin", "password123").await;
    let stats: serde_json::Value = s.get("/api/stats").await.json().await.unwrap();
    let row = stats["models"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["model"] == "claude-test")
        .expect("claude-test not in stats");
    assert_eq!(
        row["prompt_tokens"], 42,
        "input tokens from message_start were not recorded"
    );
    assert_eq!(
        row["completion_tokens"], 9,
        "output tokens from message_delta were not recorded"
    );
    assert_eq!(
        row["truncated"], 1,
        "max_tokens in message_delta was not recorded as truncation"
    );
}
