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
