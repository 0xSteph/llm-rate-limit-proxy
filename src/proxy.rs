//! The data-plane proxy: authenticate the client, acquire a rate slot, then forward
//! the request to that lane's provider and return the upstream response. Phase 1
//! buffers the response; SSE heartbeats and true streaming arrive in Phase 2.

use std::sync::atomic::Ordering;
use std::sync::Arc;

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

    // Acquire a rate slot (may wait through pacing), then forward to that lane.
    let permit = state.dispatch.acquire().await;
    let path_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/v1");
    let url = format!("{}{}", permit.base_url, path_query);

    let rq_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST);
    let mut rb = state.http.request(rq_method, &url);
    for (name, value) in headers.iter() {
        if name.as_str().eq_ignore_ascii_case("authorization") || is_hop_by_hop(name.as_str()) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            rb = rb.header(name.as_str(), v);
        }
    }
    let upstream = match rb
        .header("authorization", format!("Bearer {}", permit.key))
        .body(body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return err(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                &format!("upstream request failed: {e}"),
            )
        }
    };

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
