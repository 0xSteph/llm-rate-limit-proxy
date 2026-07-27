//! The data-plane proxy: authenticate the client, acquire a rate slot, then forward
//! the request to that lane's provider and return the upstream response. Phase 1
//! buffers the response; SSE heartbeats and true streaming arrive in Phase 2.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::{auth, AppState};

fn err(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({"error": {"message": message, "code": code}})),
    )
        .into_response()
}

/// Optional absolute wall-clock budget for the whole request (queue + retries +
/// upstream), set by the client via this header.
const DEADLINE_HEADER: &str = "x-sluice-deadline-ms";

fn parse_deadline(headers: &HeaderMap) -> Option<Instant> {
    headers
        .get(DEADLINE_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|ms| Instant::now() + Duration::from_millis(ms))
}

/// Run `fut` unless the deadline elapses first; `None` means the deadline hit.
async fn with_deadline<F: std::future::Future>(
    deadline: Option<Instant>,
    fut: F,
) -> Option<F::Output> {
    match deadline {
        Some(d) => {
            let rem = d.saturating_duration_since(Instant::now());
            tokio::time::timeout(rem, fut).await.ok()
        }
        None => Some(fut.await),
    }
}

fn deadline_exceeded() -> Response {
    err(
        StatusCode::GATEWAY_TIMEOUT,
        "deadline_exceeded",
        "request deadline exceeded",
    )
}

/// Headers we never copy from client→upstream or upstream→client.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

pub async fn handle(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if state.setup_required.load(Ordering::Relaxed) {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "setup_required",
            "setup required",
        );
    }

    // Keyed auth: a valid client key must be presented.
    let clients = { state.store.lock().unwrap().clients.clone() };
    let authed = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .and_then(|k| auth::verify_client_key(k, &clients))
        .is_some();
    if !authed {
        return err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid API key",
        );
    }

    if state.pool.read().unwrap().is_empty() {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_capacity",
            "no enabled provider keys",
        );
    }

    // Forward with automatic failover: on a retryable status or a connect error,
    // exclude that lane and try a different key, up to a few distinct lanes. The
    // last attempt's response (or a 502) is relayed as-is.
    let path_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/v1");
    let rq_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST);
    let fwd_headers: Vec<(String, String)> = headers
        .iter()
        .filter(|(n, _)| {
            !n.as_str().eq_ignore_ascii_case("authorization") && !is_hop_by_hop(n.as_str())
        })
        .filter_map(|(n, v)| {
            v.to_str()
                .ok()
                .map(|v| (n.as_str().to_string(), v.to_string()))
        })
        .collect();

    let deadline = parse_deadline(&headers);
    let max_attempts = state.pool.read().unwrap().len().clamp(1, 4);
    let mut excluded: Vec<usize> = Vec::new();
    loop {
        let permit =
            match with_deadline(deadline, state.dispatch.acquire_excluding(&excluded)).await {
                Some(p) => p,
                None => return deadline_exceeded(),
            };
        let url = format!("{}{}", permit.base_url, path_query);
        let mut rb = state.http.request(rq_method.clone(), &url);
        for (n, v) in &fwd_headers {
            rb = rb.header(n, v);
        }
        let send = rb
            .header("authorization", format!("Bearer {}", permit.key))
            .body(body.clone())
            .send();
        let sent = match with_deadline(deadline, send).await {
            Some(r) => r,
            None => return deadline_exceeded(),
        };

        let is_last = excluded.len() + 1 >= max_attempts;
        match sent {
            Ok(resp) => {
                if is_retryable(resp.status().as_u16()) && !is_last {
                    excluded.push(permit.lane_idx);
                    continue;
                }
                return relay(resp).await;
            }
            Err(e) => {
                if !is_last {
                    excluded.push(permit.lane_idx);
                    continue;
                }
                return err(
                    StatusCode::BAD_GATEWAY,
                    "upstream_error",
                    &format!("upstream request failed: {e}"),
                );
            }
        }
    }
}

fn is_retryable(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

/// Relay an upstream response back to the client (status + content-type + body).
async fn relay(upstream: reqwest::Response) -> Response {
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut out = HeaderMap::new();
    if let Some(ct) = upstream.headers().get(reqwest::header::CONTENT_TYPE) {
        if let Ok(v) = HeaderValue::from_bytes(ct.as_bytes()) {
            out.insert(header::CONTENT_TYPE, v);
        }
    }
    let payload = upstream.bytes().await.unwrap_or_default();
    (status, out, payload).into_response()
}
