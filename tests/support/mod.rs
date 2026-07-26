//! End-to-end test harness: boots the real `sluice` binary against a throwaway
//! DATA_DIR on a free port, waits for it to become healthy, and exposes a cookie-
//! aware HTTP client that does not auto-follow redirects (so tests can assert on
//! the fail-closed 303s).
#![allow(dead_code)]

use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub struct Server {
    child: Child,
    pub base_url: String,
    pub client: reqwest::Client,
    // Held only to keep the temp DATA_DIR alive for the server's lifetime.
    _data_dir: tempfile::TempDir,
}

impl Server {
    pub async fn start() -> Server {
        let data_dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let mut child = Command::new(env!("CARGO_BIN_EXE_sluice"))
            .env("HOST", "127.0.0.1")
            .env("PORT", port.to_string())
            .env("DATA_DIR", data_dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sluice binary");

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
