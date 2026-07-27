//! The data-plane proxy: authenticate the client, resolve the requested model to a
//! routing plan, then walk that plan — acquiring a rate slot per step, rewriting the
//! model, forwarding, and failing over on retryable errors. Buffered and streaming
//! (SSE, with heartbeats) responses share the same planning + failover logic.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::config::Alias;
use crate::dispatch::Permit;
use crate::{auth, AppState};

const HEARTBEAT: Duration = Duration::from_secs(15);

/// Optional absolute wall-clock budget for the whole request (queue + retries +
/// upstream), set by the client via this header.
const DEADLINE_HEADER: &str = "x-sluice-deadline-ms";

type Tx = tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>;

fn err(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({"error": {"message": message, "code": code}})),
    )
        .into_response()
}

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

fn is_retryable(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

// --- Routing plan ------------------------------------------------------------

/// One attempt in a request's routing plan: which provider to target (any if
/// `None`) and what model to send (unchanged if `None`).
struct PlanStep {
    provider: Option<String>,
    model: Option<String>,
}

/// Resolve the requested model to an ordered plan. An alias expands to its fallback
/// targets; a plain model becomes up to a few "any lane, unchanged model" steps so
/// key-level failover still applies.
fn resolve_plan(model: Option<&str>, aliases: &[Alias], pool_len: usize) -> Vec<PlanStep> {
    if let Some(name) = model {
        if let Some(alias) = aliases.iter().find(|a| a.name == name) {
            return alias
                .targets
                .iter()
                .map(|t| PlanStep {
                    provider: Some(t.provider.clone()),
                    model: Some(t.model.clone()),
                })
                .collect();
        }
    }
    (0..pool_len.clamp(1, 4))
        .map(|_| PlanStep {
            provider: None,
            model: None,
        })
        .collect()
}

fn requested_model(body: &Bytes) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("model").and_then(|m| m.as_str()).map(str::to_string))
}

/// Return `body` with its `model` field replaced, or unchanged if there's no
/// override or the body isn't a JSON object.
fn rewrite_model(body: &Bytes, model: Option<&str>) -> Bytes {
    let Some(model) = model else {
        return body.clone();
    };
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut() {
                obj.insert(
                    "model".to_string(),
                    serde_json::Value::String(model.to_string()),
                );
                if let Ok(bytes) = serde_json::to_vec(&v) {
                    return Bytes::from(bytes);
                }
            }
            body.clone()
        }
        Err(_) => body.clone(),
    }
}

fn build_request(
    state: &Arc<AppState>,
    permit: &Permit,
    method: &reqwest::Method,
    path_query: &str,
    fwd_headers: &[(String, String)],
    body: Bytes,
) -> reqwest::RequestBuilder {
    let url = format!("{}{}", permit.base_url, path_query);
    let mut rb = state.http.request(method.clone(), &url);
    for (n, v) in fwd_headers {
        rb = rb.header(n, v);
    }
    rb.header("authorization", format!("Bearer {}", permit.key))
        .body(body)
}

// --- Entry point -------------------------------------------------------------

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

    // Common request shape for both paths.
    let deadline = parse_deadline(&headers);
    let path_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/v1")
        .to_string();
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
    let aliases = { state.store.lock().unwrap().aliases.clone() };

    // Streaming: commit 200 text/event-stream now and drive the request in a worker
    // that heartbeats while it paces/retries, then relays the upstream SSE body.
    if wants_stream(&body) {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);
        tokio::spawn(stream_proxy(
            state.clone(),
            rq_method,
            path_query,
            fwd_headers,
            body,
            deadline,
            aliases,
            tx,
        ));
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/event-stream")],
            Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
        )
            .into_response();
    }

    // Buffered path: walk the plan, failing over on retryable errors.
    let pool_len = state.pool.read().unwrap().len();
    let plan = resolve_plan(requested_model(&body).as_deref(), &aliases, pool_len);
    let last = plan.len().saturating_sub(1);
    let mut excluded: Vec<usize> = Vec::new();
    for (i, step) in plan.iter().enumerate() {
        let is_last = i == last;
        let permit = match with_deadline(
            deadline,
            state
                .dispatch
                .acquire_for(step.provider.as_deref(), &excluded),
        )
        .await
        {
            None => return deadline_exceeded(),
            Some(None) => continue, // no eligible lane for this target
            Some(Some(p)) => p,
        };
        let out_body = rewrite_model(&body, step.model.as_deref());
        let send = build_request(
            &state,
            &permit,
            &rq_method,
            &path_query,
            &fwd_headers,
            out_body,
        )
        .send();
        let sent = match with_deadline(deadline, send).await {
            Some(r) => r,
            None => return deadline_exceeded(),
        };
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
    err(
        StatusCode::SERVICE_UNAVAILABLE,
        "no_capacity",
        "no provider lane available for the requested model",
    )
}

/// Relay a buffered upstream response back to the client.
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

// --- Streaming path ----------------------------------------------------------

/// True if the client asked for a streamed response (`"stream": true`).
fn wants_stream(body: &Bytes) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("stream").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

fn heartbeat_frame() -> Result<Bytes, std::io::Error> {
    Ok(Bytes::from_static(b": heartbeat\n\n"))
}

fn sse_error(code: &str) -> Result<Bytes, std::io::Error> {
    Ok(Bytes::from(format!(
        "event: error\ndata: {{\"error\":{{\"code\":\"{code}\"}}}}\n\n"
    )))
}

/// Acquire a slot for `provider` while emitting heartbeats so the committed stream
/// stays alive. `Ok(None)` = no eligible lane; `Err(())` = deadline or client gone.
async fn acquire_for_heartbeating(
    state: &Arc<AppState>,
    provider: Option<&str>,
    excluded: &[usize],
    deadline: Option<Instant>,
    tx: &Tx,
) -> Result<Option<Permit>, ()> {
    let acq = state.dispatch.acquire_for(provider, excluded);
    tokio::pin!(acq);
    loop {
        let beat = tokio::time::sleep(HEARTBEAT);
        tokio::pin!(beat);
        if let Some(d) = deadline {
            let dl = tokio::time::sleep(d.saturating_duration_since(Instant::now()));
            tokio::pin!(dl);
            tokio::select! {
                r = &mut acq => return Ok(r),
                _ = &mut dl => return Err(()),
                _ = &mut beat => {
                    if tx.send(heartbeat_frame()).await.is_err() { return Err(()); }
                }
            }
        } else {
            tokio::select! {
                r = &mut acq => return Ok(r),
                _ = &mut beat => {
                    if tx.send(heartbeat_frame()).await.is_err() { return Err(()); }
                }
            }
        }
    }
}

/// Worker behind a committed `text/event-stream`: walk the plan (heartbeating while
/// it paces/retries), then relay the upstream stream; terminal issues become SSE errors.
#[allow(clippy::too_many_arguments)]
async fn stream_proxy(
    state: Arc<AppState>,
    rq_method: reqwest::Method,
    path_query: String,
    fwd_headers: Vec<(String, String)>,
    body: Bytes,
    deadline: Option<Instant>,
    aliases: Vec<Alias>,
    tx: Tx,
) {
    // Immediate heartbeat so the client sees the stream is live right away.
    if tx.send(heartbeat_frame()).await.is_err() {
        return;
    }
    let pool_len = state.pool.read().unwrap().len();
    let plan = resolve_plan(requested_model(&body).as_deref(), &aliases, pool_len);
    let last = plan.len().saturating_sub(1);
    let mut excluded: Vec<usize> = Vec::new();
    for (i, step) in plan.iter().enumerate() {
        let is_last = i == last;
        let permit = match acquire_for_heartbeating(
            &state,
            step.provider.as_deref(),
            &excluded,
            deadline,
            &tx,
        )
        .await
        {
            Ok(Some(p)) => p,
            Ok(None) => continue,
            Err(()) => {
                let _ = tx.send(sse_error("deadline_exceeded")).await;
                return;
            }
        };
        let out_body = rewrite_model(&body, step.model.as_deref());
        let send = build_request(
            &state,
            &permit,
            &rq_method,
            &path_query,
            &fwd_headers,
            out_body,
        )
        .send();
        let sent = match with_deadline(deadline, send).await {
            Some(r) => r,
            None => {
                let _ = tx.send(sse_error("deadline_exceeded")).await;
                return;
            }
        };
        match sent {
            Ok(resp) => {
                if is_retryable(resp.status().as_u16()) && !is_last {
                    excluded.push(permit.lane_idx);
                    continue;
                }
                stream_body(resp, deadline, &tx).await;
                return;
            }
            Err(_) => {
                if !is_last {
                    excluded.push(permit.lane_idx);
                    continue;
                }
                let _ = tx.send(sse_error("upstream_error")).await;
                return;
            }
        }
    }
    let _ = tx.send(sse_error("no_capacity")).await;
}

/// Forward the upstream response body chunk-by-chunk into the client stream.
async fn stream_body(resp: reqwest::Response, deadline: Option<Instant>, tx: &Tx) {
    use futures_util::StreamExt;
    let mut stream = Box::pin(resp.bytes_stream());
    loop {
        match with_deadline(deadline, stream.next()).await {
            None => {
                let _ = tx.send(sse_error("deadline_exceeded")).await;
                return;
            }
            Some(None) => return, // upstream finished cleanly
            Some(Some(Ok(chunk))) => {
                if tx.send(Ok(chunk)).await.is_err() {
                    return; // client hung up
                }
            }
            Some(Some(Err(_))) => {
                let _ = tx.send(sse_error("stream_error")).await;
                return;
            }
        }
    }
}
