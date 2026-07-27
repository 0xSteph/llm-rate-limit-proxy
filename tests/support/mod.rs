//! End-to-end test harness: boots the real `sluice` binary against a throwaway
//! DATA_DIR on a free port, waits for it to become healthy, and exposes a cookie-
//! aware HTTP client that does not auto-follow redirects (so tests can assert on
//! the fail-closed 303s).
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Server {
    child: Child,
    pub base_url: String,
    pub client: reqwest::Client,
    // Held only to keep the temp DATA_DIR alive for the server's lifetime.
    _data_dir: tempfile::TempDir,
}

impl Server {
    pub async fn start() -> Server {
        Self::start_with_env(&[]).await
    }

    pub async fn start_with_env(extra: &[(&str, &str)]) -> Server {
        Self::spawn(tempfile::tempdir().unwrap(), extra).await
    }

    /// Boot with a pre-written config store (superuser already set up), for
    /// scenarios the wizard can't express — e.g. multiple provider keys.
    pub async fn start_seeded(
        store: &sluice::config::StoredConfig,
        extra: &[(&str, &str)],
    ) -> Server {
        let dir = tempfile::tempdir().unwrap();
        sluice::config::save(dir.path(), store).expect("seed config store");
        Self::spawn(dir, extra).await
    }

    async fn spawn(data_dir: tempfile::TempDir, extra: &[(&str, &str)]) -> Server {
        let port = free_port();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sluice"));
        cmd.env("HOST", "127.0.0.1")
            .env("PORT", port.to_string())
            .env("DATA_DIR", data_dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn sluice binary");

        let base_url = format!("http://127.0.0.1:{port}");
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        for _ in 0..100 {
            if let Ok(Some(status)) = child.try_wait() {
                panic!("sluice exited before becoming healthy: {status}");
            }
            if let Ok(r) = client.get(format!("{base_url}/health")).send().await {
                if r.status().is_success() {
                    return Server {
                        child,
                        base_url,
                        client,
                        _data_dir: data_dir,
                    };
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = child.kill();
        panic!("sluice did not become healthy within 10s");
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(format!("{}{path}", self.base_url))
            .send()
            .await
            .expect("GET failed")
    }

    pub async fn post_form(&self, path: &str, form: &[(&str, &str)]) -> reqwest::Response {
        self.client
            .post(format!("{}{path}", self.base_url))
            .form(form)
            .send()
            .await
            .expect("POST failed")
    }

    /// A request from a brand-new client with no cookies — an anonymous browser.
    pub async fn get_anon(&self, path: &str) -> reqwest::Response {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
            .get(format!("{}{path}", self.base_url))
            .send()
            .await
            .expect("GET failed")
    }

    pub async fn complete_wizard(
        &self,
        username: &str,
        password: &str,
        provider: &str,
        base_url: &str,
        api_key: &str,
    ) -> reqwest::Response {
        self.post_form(
            "/setup",
            &[
                ("username", username),
                ("password", password),
                ("provider_name", provider),
                ("base_url", base_url),
                ("api_key", api_key),
            ],
        )
        .await
    }

    pub async fn login(&self, username: &str, password: &str) -> reqwest::Response {
        self.post_form("/login", &[("username", username), ("password", password)])
            .await
    }

    pub async fn logout(&self) -> reqwest::Response {
        self.client
            .post(format!("{}/logout", self.base_url))
            .send()
            .await
            .expect("POST failed")
    }

    /// Complete setup and return the one-time client key from the response page.
    pub async fn complete_wizard_get_key(
        &self,
        username: &str,
        password: &str,
        provider: &str,
        base_url: &str,
        api_key: &str,
    ) -> String {
        let body = self
            .complete_wizard(username, password, provider, base_url, api_key)
            .await
            .text()
            .await
            .unwrap();
        let start = body.find("<pre>").expect("client key in setup page") + "<pre>".len();
        let end = start + body[start..].find("</pre>").expect("closing </pre>");
        body[start..end].to_string()
    }
}

/// A stand-in upstream provider: answers any path with a small JSON body, so a
/// proxied request can be observed arriving on the other side.
pub async fn start_mock_upstream() -> String {
    let app = axum::Router::new().route(
        "/{*rest}",
        axum::routing::any(|| async {
            (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                r#"{"mock":"ok"}"#,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://127.0.0.1:{port}")
}

/// A mock provider that waits `delay` before answering — used to trip deadlines.
pub async fn start_slow_mock(delay: Duration) -> String {
    let app = axum::Router::new().route(
        "/{*rest}",
        axum::routing::any(move || async move {
            tokio::time::sleep(delay).await;
            (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                r#"{"mock":"ok"}"#,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://127.0.0.1:{port}")
}

/// A mock provider that 429s any request bearing `bad_key` and 200s the rest —
/// lets a test prove the proxy fails a request over from a bad key to a good one.
pub async fn start_failover_mock(bad_key: &str) -> String {
    let bad = format!("Bearer {bad_key}");
    let app = axum::Router::new().route(
        "/{*rest}",
        axum::routing::any(move |headers: axum::http::HeaderMap| {
            let bad = bad.clone();
            async move {
                use axum::response::IntoResponse;
                let auth = headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if auth == bad {
                    (
                        axum::http::StatusCode::TOO_MANY_REQUESTS,
                        r#"{"error":"rate"}"#,
                    )
                        .into_response()
                } else {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        r#"{"mock":"ok"}"#,
                    )
                        .into_response()
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://127.0.0.1:{port}")
}

#[derive(Clone)]
struct MockState {
    violations: Arc<AtomicUsize>,
    total: Arc<AtomicUsize>,
    hits: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    limit: usize,
    window: Duration,
}

async fn enforce_handler(
    axum::extract::State(st): axum::extract::State<MockState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    st.total.fetch_add(1, Ordering::Relaxed);
    let key = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let now = Instant::now();
    let over = {
        let mut map = st.hits.lock().unwrap();
        let dq = map.entry(key).or_default();
        while let Some(&front) = dq.front() {
            if now.duration_since(front) >= st.window {
                dq.pop_front();
            } else {
                break;
            }
        }
        dq.push_back(now);
        dq.len() > st.limit
    };
    if over {
        st.violations.fetch_add(1, Ordering::Relaxed);
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            r#"{"error":"rate"}"#,
        )
            .into_response();
    }
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        r#"{"mock":"ok"}"#,
    )
        .into_response()
}

pub struct EnforcingMock {
    pub base_url: String,
    pub violations: Arc<AtomicUsize>,
    pub total: Arc<AtomicUsize>,
}

/// A mock provider that strictly enforces `limit` requests per `window` per key,
/// counting every excess as a violation — the yardstick the load test asserts on.
pub async fn start_enforcing_mock(limit: usize, window: Duration) -> EnforcingMock {
    let st = MockState {
        violations: Arc::new(AtomicUsize::new(0)),
        total: Arc::new(AtomicUsize::new(0)),
        hits: Arc::new(Mutex::new(HashMap::new())),
        limit,
        window,
    };
    let (violations, total) = (st.violations.clone(), st.total.clone());
    let app = axum::Router::new()
        .route("/{*rest}", axum::routing::any(enforce_handler))
        .with_state(st);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    EnforcingMock {
        base_url: format!("http://127.0.0.1:{port}"),
        violations,
        total,
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
