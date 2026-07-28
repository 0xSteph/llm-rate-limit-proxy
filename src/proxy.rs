//! The data-plane proxy: authenticate the client, resolve the requested model to a
//! routing plan, then walk that plan — acquiring a rate slot per step, rewriting the
//! model, forwarding, and failing over on retryable errors. Buffered and streaming
//! (SSE, with heartbeats) responses share the same planning + failover logic.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::config::Alias;
use crate::dispatch::Permit;
use crate::{auth, governor, models, AppState};

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

/// Shed response. Carries `Retry-After` so a shed client backs off instead of
/// hammering, and a distinct code so this is diagnosable apart from the other
/// 503s. The configured cap is deliberately not disclosed to callers.
fn overloaded() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "1")],
        Json(serde_json::json!({
            "error": {"message": "proxy at capacity; retry shortly", "code": "overloaded"}
        })),
    )
        .into_response()
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

/// Collapse a duplicated `/v1` prefix before forwarding.
///
/// Harnesses are configured with a base URL and their SDK appends the rest, and
/// the two conventions disagree about who owns the `/v1`: some want it in the
/// base, others prepend it themselves. Configure both and the client sends
/// `/v1/v1/chat/completions`. Forwarded as-is that hits a provider route which
/// doesn't exist, and the answer is a bare router "404 page not found" — plain
/// text, naming nothing, indistinguishable from a missing model.
///
/// No provider routes a repeated version segment, so collapsing it is always
/// what the caller meant, and being tolerant here costs a user nothing while
/// saving them an afternoon.
fn normalize_path(path_query: &str) -> String {
    let mut out = path_query.to_string();
    while let Some(rest) = out.strip_prefix("/v1/v1/") {
        out = format!("/v1/{rest}");
    }
    out
}

/// Longest we honor a provider's `Retry-After`. Beyond this the value is more
/// likely wrong than real, and obeying it would park a paid key for no reason.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

/// How long the provider asked us to stay away, from `Retry-After`. Only the
/// delta-seconds form is read — RFC 9110 also allows an HTTP-date, which needs a
/// date parser we don't carry; that form reads as "no guidance" so the caller
/// falls back to its own backoff instead of guessing at zero.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let raw = headers.get(header::RETRY_AFTER)?.to_str().ok()?;
    let secs: u64 = raw.trim().parse().ok()?;
    Some(Duration::from_secs(secs).min(MAX_RETRY_AFTER))
}

/// Holds one concurrency slot, releasing it on drop so a request frees its slot
/// however it ends — success, error, deadline, or the client hanging up mid-stream
/// — without every exit path having to remember.
pub struct InflightGuard(Arc<AtomicUsize>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Claim a concurrency slot, or `None` when the proxy is already at `max`.
///
/// The slot is claimed first and handed back on refusal, so the check is a single
/// atomic and concurrent callers can never both observe room and overshoot the cap
/// the way a separate load-then-increment can.
pub fn try_admit(counter: &Arc<AtomicUsize>, max: usize) -> Option<InflightGuard> {
    if counter.fetch_add(1, Ordering::Relaxed) >= max {
        counter.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    Some(InflightGuard(counter.clone()))
}

/// How often a request blocked by model pressure re-checks for a free permit.
/// Slots free stochastically as generations finish, so polling fits better than
/// a queue: there is no moment to wake a specific waiter.
const GOVERNOR_POLL: Duration = Duration::from_millis(250);

/// Wait for a model-concurrency permit, giving up if the deadline would pass
/// first. Ungoverned models return immediately. `beat` is invoked once per poll
/// so a committed stream can keep its client alive; returning false means the
/// client is gone.
async fn admit_model(
    state: &Arc<AppState>,
    model: &str,
    deadline: Option<Instant>,
    mut beat: impl FnMut() -> bool,
) -> Option<governor::ModelPermit> {
    loop {
        if let Some(permit) = governor::admit(&state.governor, model, Instant::now()) {
            return Some(permit);
        }
        if deadline.is_some_and(|d| Instant::now() + GOVERNOR_POLL >= d) {
            return None;
        }
        tokio::time::sleep(GOVERNOR_POLL).await;
        if !beat() {
            return None;
        }
    }
}

/// Cooldown for a lane the provider rebuffed without saying for how long.
const DEFAULT_BENCH: Duration = Duration::from_secs(5);

/// Take the rebuffed lane out of rotation for as long as the provider asked, or
/// a short default. A key that just answered 429 will answer the same way to the
/// next request, so without this every request pays to rediscover it.
fn bench_lane(state: &AppState, lane_idx: usize, headers: &HeaderMap) {
    let cooldown = retry_after(headers).unwrap_or(DEFAULT_BENCH);
    let pool = state.pool.read().unwrap().clone();
    if let Some(lane) = pool.lanes().get(lane_idx) {
        lane.bench(Instant::now() + cooldown);
    }
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

/// Conversation identity for sticky routing: the model plus the opening messages.
/// An agent session appends to its transcript every turn but never rewrites the
/// head, so hashing the head yields the same value each turn while the tail grows
/// — which is exactly the prefix the upstream would have cached. `None` for
/// requests with no `messages` array, which carry no conversation to pin.
fn session_key(body: &Bytes) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let messages = v.get("messages")?.as_array()?;
    let mut h = DefaultHasher::new();
    v.get("model")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .hash(&mut h);
    for msg in messages.iter().take(2) {
        msg.to_string().hash(&mut h);
    }
    Some(h.finish())
}

/// Ask the upstream to report exact token counts in the final SSE frame by
/// setting `stream_options.include_usage`.
///
/// Without it a streamed response carries no usage at all and token figures have
/// to be guessed from frame counts. Returns `None` when there is nothing to do:
/// a body that isn't a JSON object, or one where the client already set
/// `stream_options` — their choice wins over our accounting.
fn inject_usage(body: &Bytes) -> Option<Bytes> {
    let mut v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let obj = v.as_object_mut()?;
    if obj.contains_key("stream_options") {
        return None;
    }
    obj.insert(
        "stream_options".to_string(),
        serde_json::json!({"include_usage": true}),
    );
    serde_json::to_vec(&v).ok().map(Bytes::from)
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

// --- Model catalog -----------------------------------------------------------

/// Answer `/v1/models` by merging every provider's catalog with the configured
/// aliases, refreshing any provider whose copy has expired.
async fn serve_catalog(
    state: &Arc<AppState>,
    aliases: &[Alias],
    deadline: Option<Instant>,
) -> Response {
    let providers: Vec<String> = {
        let store = state.store.lock().unwrap();
        store.providers.iter().map(|p| p.name.clone()).collect()
    };

    let mut catalogs = Vec::with_capacity(providers.len());
    for provider in &providers {
        if let Some(cached) = state.catalog.fresh(provider, Instant::now()) {
            catalogs.push(cached);
            continue;
        }
        match fetch_catalog(state, provider, deadline).await {
            Some(models) => {
                state.catalog.put(provider, models.clone(), Instant::now());
                catalogs.push(models);
            }
            // One provider being unreachable must not blank the whole catalog:
            // fall back to what we last saw, and simply omit a provider we have
            // never reached.
            None => {
                if let Some(stale) = state.catalog.stale(provider) {
                    catalogs.push(stale);
                }
            }
        }
    }

    Json(models::merge(&catalogs, aliases)).into_response()
}

/// Fetch one provider's catalog. Takes a rate slot like any other upstream call
/// — it is a real request against that key's budget, cache or not.
async fn fetch_catalog(
    state: &Arc<AppState>,
    provider: &str,
    deadline: Option<Instant>,
) -> Option<Vec<serde_json::Value>> {
    let permit = with_deadline(
        deadline,
        state.dispatch.acquire_for(Some(provider), &[], None),
    )
    .await??;
    let resp = state
        .http
        .get(format!("{}/v1/models", permit.base_url))
        .header("authorization", format!("Bearer {}", permit.key))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    Some(models::extract(&resp.json().await.ok()?))
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

    // Keyed auth: a valid client key must be presented. Its label is the metrics
    // dimension for "who" — trusted (admin-set), never the secret.
    let clients = { state.store.lock().unwrap().clients.clone() };
    let client = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .and_then(|k| auth::verify_client_key(k, &clients));
    let Some(client) = client else {
        return err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid API key",
        );
    };

    if state.pool.read().unwrap().is_empty() {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_capacity",
            "no enabled provider keys",
        );
    }

    // Shed before parsing: an agent transcript is a large body and the paths below
    // walk it more than once, so a flood must be turned away before that cost is
    // paid. The guard rides the whole request and frees its slot on drop.
    let max_inflight = { state.store.lock().unwrap().settings.max_inflight };
    let Some(inflight) = try_admit(&state.inflight, max_inflight) else {
        return overloaded();
    };

    // Common request shape for both paths.
    let deadline = parse_deadline(&headers);
    let path_query = normalize_path(uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/v1"));
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

    // Catalog requests are answered locally rather than forwarded. Forwarding
    // would spend rate budget on a poll, return whichever provider won the lane,
    // and hide every alias — which are routable names a harness can only learn
    // about from here.
    if method == Method::GET && uri.path() == "/v1/models" {
        return serve_catalog(&state, &aliases, deadline).await;
    }

    let requested = requested_model(&body);
    let model_label = requested.clone().unwrap_or_else(|| "unknown".to_string());
    let session = session_key(&body);

    // Streaming: commit 200 text/event-stream now and drive the request in a worker
    // that heartbeats while it paces/retries, then relays the upstream SSE body.
    if wants_stream(&body) {
        // Ask for exact token counts unless this model has already told us it
        // rejects the field; keep the original so that can be undone per request.
        let (out_body, fallback) = match state.no_inject.lock().unwrap().contains(&model_label) {
            true => (body.clone(), None),
            false => match inject_usage(&body) {
                Some(injected) => (injected, Some(body.clone())),
                None => (body.clone(), None),
            },
        };
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);
        tokio::spawn(stream_proxy(
            state.clone(),
            rq_method,
            path_query,
            fwd_headers,
            out_body,
            fallback,
            deadline,
            aliases,
            client,
            model_label,
            session,
            inflight,
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
    let plan = resolve_plan(requested.as_deref(), &aliases, pool_len);
    let last = plan.len().saturating_sub(1);
    let mut excluded: Vec<usize> = Vec::new();
    for (i, step) in plan.iter().enumerate() {
        let is_last = i == last;
        // Model pressure is gated before the rate slot: a request that cannot run
        // yet shouldn't be holding a key's budget while it waits.
        let step_model = step.model.as_deref().unwrap_or(&model_label);
        let Some(_model_permit) = admit_model(&state, step_model, deadline, || true).await else {
            state.metrics.record_request(&client, &model_label, "504");
            return deadline_exceeded();
        };
        let permit = match with_deadline(
            deadline,
            state
                .dispatch
                .acquire_for(step.provider.as_deref(), &excluded, session),
        )
        .await
        {
            None => {
                state.metrics.record_request(&client, &model_label, "504");
                return deadline_exceeded();
            }
            Some(None) => continue, // no eligible lane for this target
            Some(Some(p)) => p,
        };
        let out_body = rewrite_model(&body, step.model.as_deref());
        let t0 = Instant::now();
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
                state.metrics.record_request(&client, &model_label, "504");
                return deadline_exceeded();
            }
        };
        match sent {
            Ok(resp) => {
                if is_retryable(resp.status().as_u16()) {
                    // Bench even on the last step: this request is out of options,
                    // but the next one shouldn't walk into the same wall.
                    bench_lane(&state, permit.lane_idx, resp.headers());
                    state
                        .governor
                        .note_rebuff(step_model, permit.lane_idx, Instant::now());
                    if !is_last {
                        excluded.push(permit.lane_idx);
                        continue;
                    }
                }
                let status = resp.status().as_u16();
                state
                    .metrics
                    .record_request(&client, &model_label, &status.to_string());
                state
                    .metrics
                    .record_latency(&model_label, t0.elapsed().as_millis() as u64);
                state.metrics.record_lane(&permit.provider);
                return relay(&state, &model_label, resp).await;
            }
            Err(e) => {
                if !is_last {
                    excluded.push(permit.lane_idx);
                    continue;
                }
                state.metrics.record_request(&client, &model_label, "502");
                return err(
                    StatusCode::BAD_GATEWAY,
                    "upstream_error",
                    &format!("upstream request failed: {e}"),
                );
            }
        }
    }
    state.metrics.record_request(&client, &model_label, "503");
    err(
        StatusCode::SERVICE_UNAVAILABLE,
        "no_capacity",
        "no provider lane available for the requested model",
    )
}

/// Relay a buffered upstream response back to the client, recording token usage
/// (content-blind — only the counts from the `usage` object, never the text).
async fn relay(state: &Arc<AppState>, model: &str, upstream: reqwest::Response) -> Response {
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut out = HeaderMap::new();
    if let Some(ct) = upstream.headers().get(reqwest::header::CONTENT_TYPE) {
        if let Ok(v) = HeaderValue::from_bytes(ct.as_bytes()) {
            out.insert(header::CONTENT_TYPE, v);
        }
    }
    let payload = upstream.bytes().await.unwrap_or_default();
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&payload) {
        if let Some(u) = v.get("usage") {
            let p = u.get("prompt_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
            let c = u
                .get("completion_tokens")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            if p > 0 || c > 0 {
                state.metrics.record_tokens(model, p, c);
            }
        }
    }
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
    session: Option<u64>,
    deadline: Option<Instant>,
    tx: &Tx,
) -> Result<Option<Permit>, ()> {
    let acq = state.dispatch.acquire_for(provider, excluded, session);
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
    mut body: Bytes,
    // The client's original body, kept only while we have added `stream_options`
    // to it, so the addition can be undone if this model rejects the field.
    mut fallback: Option<Bytes>,
    deadline: Option<Instant>,
    aliases: Vec<Alias>,
    client: String,
    model: String,
    session: Option<u64>,
    // Held for the life of the stream so `max_inflight` bounds live streams too,
    // not just the brief window before the response is committed.
    _inflight: InflightGuard,
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
    let mut retried_plain = false;
    for (i, step) in plan.iter().enumerate() {
        let is_last = i == last;
        // Heartbeat while waiting on model pressure: the 200 is already committed,
        // so a silent wait here would look like a hung stream to the client.
        let step_model = step.model.as_deref().unwrap_or(&model);
        let beat = || tx.try_send(heartbeat_frame()).is_ok() || !tx.is_closed();
        let Some(_model_permit) = admit_model(&state, step_model, deadline, beat).await else {
            state.metrics.record_request(&client, &model, "504");
            let _ = tx.send(sse_error("deadline_exceeded")).await;
            return;
        };
        let permit = match acquire_for_heartbeating(
            &state,
            step.provider.as_deref(),
            &excluded,
            session,
            deadline,
            &tx,
        )
        .await
        {
            Ok(Some(p)) => p,
            Ok(None) => continue,
            Err(()) => {
                state.metrics.record_request(&client, &model, "504");
                let _ = tx.send(sse_error("deadline_exceeded")).await;
                return;
            }
        };
        let sent = loop {
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
                    state.metrics.record_request(&client, &model, "504");
                    let _ = tx.send(sse_error("deadline_exceeded")).await;
                    return;
                }
            };
            // A 400 right after we added `stream_options` points at this model
            // rejecting the field. Retry this same step with the client's original
            // body — a rejection we caused must not become the client's error.
            if matches!(&sent, Ok(r) if r.status() == reqwest::StatusCode::BAD_REQUEST)
                && fallback.is_some()
            {
                body = fallback.take().expect("checked above");
                retried_plain = true;
                continue;
            }
            break sent;
        };
        match sent {
            Ok(resp) => {
                if is_retryable(resp.status().as_u16()) {
                    bench_lane(&state, permit.lane_idx, resp.headers());
                    state
                        .governor
                        .note_rebuff(step_model, permit.lane_idx, Instant::now());
                    if !is_last {
                        excluded.push(permit.lane_idx);
                        continue;
                    }
                }
                // Only learn from a retry that actually worked. Recording the model
                // on the 400 alone would blame our injection for a body the client
                // simply got wrong, and permanently give up exact token counts.
                if retried_plain && resp.status().is_success() {
                    state.no_inject.lock().unwrap().insert(model.clone());
                }
                state.metrics.record_request(&client, &model, "200");
                state.metrics.record_lane(&permit.provider);
                stream_body(resp, deadline, &tx).await;
                return;
            }
            Err(_) => {
                if !is_last {
                    excluded.push(permit.lane_idx);
                    continue;
                }
                state.metrics.record_request(&client, &model, "502");
                let _ = tx.send(sse_error("upstream_error")).await;
                return;
            }
        }
    }
    state.metrics.record_request(&client, &model, "503");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn with_retry_after(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::RETRY_AFTER, HeaderValue::from_str(v).unwrap());
        h
    }

    #[test]
    fn admission_stops_at_the_cap_and_frees_on_drop() {
        let counter = Arc::new(AtomicUsize::new(0));
        let first = try_admit(&counter, 2).expect("first admitted");
        let second = try_admit(&counter, 2).expect("second admitted");
        assert!(try_admit(&counter, 2).is_none(), "third exceeds the cap");
        drop(first);
        assert!(try_admit(&counter, 2).is_some(), "a freed slot is reusable");
        drop(second);
    }

    /// The counter is claimed before the cap is checked, so a refusal has to put
    /// it back — otherwise every shed permanently shrinks the pool by one and the
    /// proxy strangles itself under exactly the load the cap exists to survive.
    #[test]
    fn refused_admissions_do_not_leak_slots() {
        let counter = Arc::new(AtomicUsize::new(0));
        let _held = try_admit(&counter, 1).expect("first admitted");
        for _ in 0..5 {
            assert!(try_admit(&counter, 1).is_none());
        }
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    /// The single most common harness misconfiguration. Two conventions disagree
    /// about who owns the `/v1`: some SDKs want it in the base URL, others prepend
    /// it themselves. Set both and the client sends `/v1/v1/chat/completions`,
    /// which forwards to a provider route that does not exist and returns a bare
    /// "404 page not found" naming nothing and pointing at nothing.
    #[test]
    fn a_doubled_version_prefix_is_collapsed() {
        assert_eq!(
            normalize_path("/v1/v1/chat/completions"),
            "/v1/chat/completions"
        );
        assert_eq!(normalize_path("/v1/v1/v1/models"), "/v1/models");
    }

    #[test]
    fn a_correct_path_is_left_alone() {
        assert_eq!(
            normalize_path("/v1/chat/completions"),
            "/v1/chat/completions"
        );
        assert_eq!(normalize_path("/v1/models"), "/v1/models");
    }

    #[test]
    fn collapsing_preserves_the_query_string() {
        assert_eq!(
            normalize_path("/v1/v1/models?limit=5"),
            "/v1/models?limit=5"
        );
    }

    /// Only a whole `/v1` segment counts — a path that merely starts with those
    /// characters is a different route.
    #[test]
    fn a_similar_looking_segment_is_not_treated_as_a_duplicate() {
        assert_eq!(normalize_path("/v1/v1beta/x"), "/v1/v1beta/x");
    }

    #[test]
    fn usage_injection_adds_include_usage() {
        let out = inject_usage(&Bytes::from(r#"{"model":"m","stream":true}"#)).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["stream_options"]["include_usage"], true);
        assert_eq!(v["model"], "m", "the rest of the body is untouched");
    }

    /// A client that set `stream_options` itself meant it. Our token accounting
    /// is not a good enough reason to overwrite what they asked for.
    #[test]
    fn usage_injection_leaves_a_clients_own_stream_options_alone() {
        let body = Bytes::from(r#"{"model":"m","stream_options":{"include_usage":false}}"#);
        assert!(inject_usage(&body).is_none());
    }

    #[test]
    fn usage_injection_declines_bodies_it_cannot_parse() {
        assert!(inject_usage(&Bytes::from("not json")).is_none());
        assert!(inject_usage(&Bytes::from("[1,2,3]")).is_none());
    }

    #[test]
    fn retry_after_reads_delta_seconds() {
        assert_eq!(
            retry_after(&with_retry_after("5")),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn retry_after_is_none_without_the_header() {
        assert_eq!(retry_after(&HeaderMap::new()), None);
    }

    #[test]
    fn retry_after_ignores_values_it_cannot_read() {
        // The HTTP-date form is valid per RFC 9110 but unsupported here. It has to
        // read as "no guidance" so the caller uses its own backoff, never as zero.
        assert_eq!(
            retry_after(&with_retry_after("Wed, 21 Oct 2026 07:28:00 GMT")),
            None
        );
        assert_eq!(retry_after(&with_retry_after("soon")), None);
    }

    #[test]
    fn retry_after_clamps_absurd_backoffs() {
        // A buggy or hostile upstream must not be able to park a key for a day.
        assert_eq!(
            retry_after(&with_retry_after("86400")),
            Some(MAX_RETRY_AFTER)
        );
    }
}
