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

use crate::config::{Alias, Protocol};
use crate::dispatch::Permit;
use crate::{auth, governor, models, AppState};

const HEARTBEAT: Duration = Duration::from_secs(15);

/// Optional absolute wall-clock budget for the whole request (queue + retries +
/// upstream), set by the client via this header.
const DEADLINE_HEADER: &str = "x-llm-rate-limit-proxy-deadline-ms";

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
    // Counted by the caller via record_event("deadline") where the state is in
    // scope; this only builds the response.
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

/// Statuses worth another attempt on a different key.
///
/// 529 is not in any RFC but providers use it for "temporarily overloaded" —
/// NVIDIA returned it in production and it went straight to the client as a
/// terminal error, which is the opposite of what it means. 408 is the same
/// shape: the request timed out, not the request was wrong.
fn is_retryable(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504 | 529)
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

/// The Anthropic API version to send when a client did not pick one. Pinned
/// rather than tracking latest: the version decides the response shape, and
/// silently moving it would change what clients receive without them asking.
const ANTHROPIC_VERSION: &str = "2023-06-01";

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

/// Record a finished request: one metric, one log line.
///
/// The **path** is in the line deliberately. A misconfigured harness sends a
/// path the proxy forwards verbatim, and the provider answers a bare 404 that
/// names nothing. Seeing `/v1/v1/chat/completions` in the log is the difference
/// between diagnosing that in seconds and guessing at it for an afternoon.
fn record(
    state: &AppState,
    client: &str,
    model: &str,
    path: &str,
    status: &str,
    lane: Option<usize>,
    started: Instant,
) {
    state.metrics.record_request(client, model, status);
    // Which key carried it. For a key-rotation proxy this is the one field that
    // answers "is rotation actually spreading load", and its absence hides a
    // pool quietly collapsing onto one key.
    let key = match lane {
        Some(i) => format!("key#{i}"),
        None => "-".to_string(),
    };
    println!(
        "{status} {client} {key} {model} {path} ({} ms)",
        started.elapsed().as_millis()
    );
}

/// Cooldown for a lane the provider rebuffed without saying for how long.
const DEFAULT_BENCH: Duration = Duration::from_secs(5);

/// Take the rebuffed lane out of rotation for as long as the provider asked, or
/// a short default. A key that just answered 429 will answer the same way to the
/// next request, so without this every request pays to rediscover it.
fn bench_lane(state: &AppState, lane_idx: usize, model: &str, status: u16, headers: &HeaderMap) {
    let cooldown = retry_after(headers).unwrap_or(DEFAULT_BENCH);
    let pool = state.pool.read().unwrap().clone();
    if let Some(lane) = pool.lanes().get(lane_idx) {
        lane.bench(Instant::now() + cooldown);
        state.metrics.record_event("lane_benched");
        // Retries are invisible in the access log, which only records how a
        // request finally ended. Without this line an operator can see that the
        // governor engaged but has no way to count the pushback behind it.
        println!(
            "  retry {status} {} key#{lane_idx} {model} (benched {}s)",
            lane.provider,
            cooldown.as_secs()
        );
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
fn resolve_plan(
    model: Option<&str>,
    aliases: &[Alias],
    pool_len: usize,
    offering: &[String],
) -> Vec<PlanStep> {
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
    // Try the providers whose catalog actually lists this model first. Sending it
    // to one that doesn't spends a rate slot to earn a 404 and then fails over,
    // so with several providers configured this is the difference between one
    // clean call and a tour of every key.
    let mut steps: Vec<PlanStep> = offering
        .iter()
        .map(|p| PlanStep {
            provider: Some(p.clone()),
            model: None,
        })
        .collect();
    // Always keep at least one unrestricted attempt: a catalog can be stale, or
    // never fetched at all, and being wrong about that must not strand a request.
    let anywhere = pool_len.clamp(1, 4).saturating_sub(steps.len()).max(1);
    steps.extend((0..anywhere).map(|_| PlanStep {
        provider: None,
        model: None,
    }));
    steps
}

fn requested_model(body: &serde_json::Value) -> Option<String> {
    body.get("model")
        .and_then(|m| m.as_str())
        .map(str::to_string)
}

/// Conversation identity for sticky routing: the model plus the opening messages.
/// An agent session appends to its transcript every turn but never rewrites the
/// head, so hashing the head yields the same value each turn while the tail grows
/// — which is exactly the prefix the upstream would have cached. `None` for
/// requests with no `messages` array, which carry no conversation to pin.
fn session_key(body: &serde_json::Value) -> Option<u64> {
    let messages = body.get("messages")?.as_array()?;
    let mut h = DefaultHasher::new();
    body.get("model")
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
fn inject_usage(body: &serde_json::Value) -> Option<Bytes> {
    let mut v = body.clone();
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
    match permit.protocol {
        Protocol::OpenAi => rb.header("authorization", format!("Bearer {}", permit.key)),
        // Anthropic authenticates with `x-api-key` and requires a version on every
        // request. A client that sent its own version keeps it: that header pins
        // the response shape it is prepared to parse, which is its call, not ours.
        Protocol::Anthropic => {
            let rb = rb.header("x-api-key", permit.key.as_str());
            if fwd_headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("anthropic-version"))
            {
                rb
            } else {
                rb.header("anthropic-version", ANTHROPIC_VERSION)
            }
        }
    }
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

    Json(models::merge(&catalogs, aliases, &state.context_limits)).into_response()
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
        state.dispatch.acquire_for(Some(provider), &[], None, None),
    )
    .await??;
    let rb = state.http.get(format!("{}/v1/models", permit.base_url));
    let rb = match permit.protocol {
        Protocol::OpenAi => rb.header("authorization", format!("Bearer {}", permit.key)),
        Protocol::Anthropic => rb
            .header("x-api-key", permit.key.as_str())
            .header("anthropic-version", ANTHROPIC_VERSION),
    };
    let resp = rb.send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    // Deserialize via serde_json rather than reqwest's `json()`: that helper sits
    // behind a feature only the dev-dependency enables, so using it here builds
    // under `cargo test` (features unify across dev-deps) and fails a real build.
    let body = resp.bytes().await.ok()?;
    Some(models::extract(&serde_json::from_slice(&body).ok()?))
}

// --- Entry point -------------------------------------------------------------

pub async fn handle(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Wall clock for the access line: what the client actually waited, including
    // queueing and retries, not just the last upstream hop.
    let t0 = Instant::now();
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
    // Anthropic-native clients send `x-api-key`; the OpenAI world sends
    // `Authorization: Bearer`. Accept either, so a client authenticates the way
    // its own protocol says to rather than the way this proxy would prefer.
    let client = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
        .and_then(|k| auth::verify_client_key(k, &clients));
    let Some(client) = client else {
        state.metrics.record_event("unauthorized");
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
        state.metrics.record_event("shed");
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
            !n.as_str().eq_ignore_ascii_case("authorization")
                && !n.as_str().eq_ignore_ascii_case("x-api-key")
                && !is_hop_by_hop(n.as_str())
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
    // Matched on the normalized path, not the raw one: a harness sending the
    // doubled prefix asks for its catalog down the same wrong path as everything
    // else, and routing decisions must see what forwarding will see.
    let route = path_query.split('?').next().unwrap_or_default();
    // Which shape the client is speaking. Decided by route because that is the
    // only thing true before the body is parsed, and it has to hold for bodies
    // that are not JSON at all.
    let wire = Protocol::of_route(route);
    if method == Method::GET && route == "/v1/models" {
        return serve_catalog(&state, &aliases, deadline).await;
    }

    // `/v1/props` is llama.cpp's, and harnesses poll it for `n_ctx` because it is
    // the only endpoint in common use that states a context window at all. Left
    // unhandled it forwards upstream, spends a rate slot, and earns a 404 — so a
    // client asking the one question we can now answer gets nothing, and pays for
    // the privilege.
    //
    // Answered only once a ceiling has actually been learned. A guess here is
    // worse than silence: silence leaves the client on its own default, while a
    // wrong n_ctx is a number it will trust.
    if method == Method::GET && route == "/v1/props" {
        let Some(n_ctx) = state.context_limits.smallest() else {
            return err(
                StatusCode::NOT_FOUND,
                "unknown_context",
                "no context window observed yet for any model",
            );
        };
        record(&state, &client, "props", &path_query, "200", None, t0);
        return Json(serde_json::json!({
            "default_generation_settings": { "n_ctx": n_ctx },
            "n_ctx": n_ctx,
            "total_slots": 1,
        }))
        .into_response();
    }

    // Parsed exactly once. Four helpers need to look inside the body and an
    // agent transcript is the largest thing this process handles, so parsing it
    // per-helper was the most expensive avoidable work on the hot path. A body
    // that isn't JSON simply answers `None` to all of them and is forwarded
    // untouched, which is what a passthrough proxy should do anyway.
    let parsed: Option<serde_json::Value> = serde_json::from_slice(&body).ok();
    let requested = parsed.as_ref().and_then(requested_model);
    let model_label = requested.clone().unwrap_or_else(|| "unknown".to_string());
    let session = parsed.as_ref().and_then(session_key);

    // What the harness asked for, in counts and sizes only. Conversation depth
    // and output budget are the two that explain a bill; temperature and tool
    // count explain behaviour that otherwise looks like the model changing.
    if let Some(v) = parsed.as_ref() {
        let n = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_array())
                .map(|a| a.len() as u64)
                .unwrap_or(0)
        };
        let temp_x100 = v
            .get("temperature")
            .and_then(|t| t.as_f64())
            .map(|t| (t * 100.0) as u64)
            .unwrap_or(0);
        let max_tok = v.get("max_tokens").and_then(|t| t.as_u64()).unwrap_or(0);
        state
            .metrics
            .record_shape(&client, n("messages"), n("tools"), max_tok, temp_x100);
    }
    let streaming = parsed.as_ref().is_some_and(wants_stream);
    state.metrics.record_stream_mix(streaming);
    let _active = state.metrics.track_active();

    // Streaming: commit 200 text/event-stream now and drive the request in a worker
    // that heartbeats while it paces/retries, then relays the upstream SSE body.
    if streaming {
        // Ask for exact token counts unless this model has already told us it
        // rejects the field; keep the original so that can be undone per request.
        // OpenAI only. Anthropic reports usage in `message_start` and
        // `message_delta` without being asked, and rejects unknown top-level
        // fields — so adding `stream_options` there turns a good request into a
        // 400.
        let injected = (wire == Protocol::OpenAi
            && !state.no_inject.lock().unwrap().contains(&model_label))
        .then(|| parsed.as_ref().and_then(inject_usage))
        .flatten();
        let (out_body, fallback) = match injected {
            Some(with_usage) => (with_usage, Some(body.clone())),
            None => (body.clone(), None),
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
            requested,
            session,
            wire,
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
    let offering = state.catalog.providers_offering(&model_label);
    let plan = resolve_plan(requested.as_deref(), &aliases, pool_len, &offering);
    let last = plan.len().saturating_sub(1);
    let mut excluded: Vec<usize> = Vec::new();
    for (i, step) in plan.iter().enumerate() {
        let is_last = i == last;
        // Model pressure is gated before the rate slot: a request that cannot run
        // yet shouldn't be holding a key's budget while it waits.
        let step_model = step.model.as_deref().unwrap_or(&model_label);
        let Some(_model_permit) = admit_model(&state, step_model, deadline, || true).await else {
            state.metrics.record_event("deadline");
            record(&state, &client, &model_label, &path_query, "504", None, t0);
            return deadline_exceeded();
        };
        let queued_at = Instant::now();
        let permit = match with_deadline(
            deadline,
            state
                .dispatch
                .acquire_for(step.provider.as_deref(), &excluded, session, Some(wire)),
        )
        .await
        {
            None => {
                state.metrics.record_event("deadline");
                record(&state, &client, &model_label, &path_query, "504", None, t0);
                return deadline_exceeded();
            }
            Some(None) => continue, // no eligible lane for this target
            Some(Some(p)) => p,
        };
        // Distinguishes "our pool is the bottleneck" from "the provider is
        // slow" — end to end they look identical.
        state
            .metrics
            .record_queue_wait(queued_at.elapsed().as_millis() as u64);
        let out_body = rewrite_model(&body, step.model.as_deref());
        let upstream_at = Instant::now();
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
                state.metrics.record_event("deadline");
                record(&state, &client, &model_label, &path_query, "504", None, t0);
                return deadline_exceeded();
            }
        };
        match sent {
            Ok(resp) => {
                if is_retryable(resp.status().as_u16()) {
                    // Bench even on the last step: this request is out of options,
                    // but the next one shouldn't walk into the same wall.
                    bench_lane(
                        &state,
                        permit.lane_idx,
                        step_model,
                        resp.status().as_u16(),
                        resp.headers(),
                    );
                    state
                        .governor
                        .note_rebuff(step_model, permit.lane_idx, Instant::now());
                    if !is_last {
                        excluded.push(permit.lane_idx);
                        continue;
                    }
                }
                let status = resp.status().as_u16();
                record(
                    &state,
                    &client,
                    &model_label,
                    &path_query,
                    &status.to_string(),
                    Some(permit.lane_idx),
                    t0,
                );
                state
                    .metrics
                    .record_latency(&model_label, upstream_at.elapsed().as_millis() as u64);
                state.metrics.record_lane(&permit.provider);
                // On a buffered call the server generates the whole answer before
                // it sends anything, so "time to first byte" and "total time" are
                // the same number and there is no separate generation window.
                // Recording it as TTFT is still true — it is when the client
                // could first have seen anything — but the speed calculation has
                // to span the whole upstream exchange, not the part after
                // headers, which is why that column read zero.
                state
                    .metrics
                    .record_ttft(&model_label, upstream_at.elapsed().as_millis() as u64);
                // The body is read inside relay, so the clock has to be handed
                // in and stopped there. Calling elapsed() here measured the gap
                // between two adjacent statements — always zero, which is
                // exactly what the tokens/sec column showed.
                return relay(&state, &model_label, upstream_at, resp).await;
            }
            Err(e) => {
                if !is_last {
                    excluded.push(permit.lane_idx);
                    continue;
                }
                record(
                    &state,
                    &client,
                    &model_label,
                    &path_query,
                    "502",
                    Some(permit.lane_idx),
                    t0,
                );
                return err(
                    StatusCode::BAD_GATEWAY,
                    "upstream_error",
                    &format!("upstream request failed: {e}"),
                );
            }
        }
    }
    record(&state, &client, &model_label, &path_query, "503", None, t0);
    err(
        StatusCode::SERVICE_UNAVAILABLE,
        "no_capacity",
        "no provider lane available for the requested model",
    )
}

/// Learn a model's context ceiling from the provider's own complaint about it.
///
/// Nothing in the OpenAI protocol publishes a context window — `/v1/models`
/// carries no such field — so every client is left to guess, and a guess that is
/// too high fails deep into a long session rather than at configuration time.
/// The providers do know the number, but only say it in the error you get for
/// exceeding it. Capturing it there turns a single overflow into a fact the
/// catalog can hand to every client afterwards.
fn parse_context_limit(body: &str) -> Option<u64> {
    const MARKER: &str = "maximum context length is ";
    let rest = &body[body.find(MARKER)? + MARKER.len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Did upstream answer `200 OK` with a completion containing nothing?
///
/// NVIDIA does exactly this when a request's input plus its `max_tokens` exceeds
/// the model's window: no choices, null usage, and no error of any kind. Only
/// overflowing on input *alone* produces an honest 400. Relaying the empty one
/// unchanged hands the client a success carrying no answer, which surfaces in an
/// agent harness as an internal error pointing nowhere near the real cause.
///
/// Streaming chunks legitimately carry an empty `choices` array, so this matches
/// on the buffered `chat.completion` object only.
fn is_empty_completion(v: &serde_json::Value) -> bool {
    v.get("object").and_then(|o| o.as_str()) == Some("chat.completion")
        && v.get("choices")
            .and_then(|c| c.as_array())
            .is_some_and(|c| c.is_empty())
}

/// Relay a buffered upstream response back to the client, recording token usage
/// (content-blind — only the counts from the `usage` object, never the text).
async fn relay(
    state: &Arc<AppState>,
    model: &str,
    gen_start: Instant,
    upstream: reqwest::Response,
) -> Response {
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut out = HeaderMap::new();
    if let Some(ct) = upstream.headers().get(reqwest::header::CONTENT_TYPE) {
        if let Ok(v) = HeaderValue::from_bytes(ct.as_bytes()) {
            out.insert(header::CONTENT_TYPE, v);
        }
    }
    let payload = upstream.bytes().await.unwrap_or_default();
    let gen_ms = gen_start.elapsed().as_millis() as u64;
    // A refusal for being too long is the only place the real context window is
    // ever stated. Catch it in passing so the catalog can publish it afterwards.
    if !status.is_success() {
        if let Some(n) = std::str::from_utf8(&payload)
            .ok()
            .and_then(parse_context_limit)
        {
            state.context_limits.learn(model, n);
        }
    }
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&payload) {
        if status.is_success() && is_empty_completion(&v) {
            return err(
                StatusCode::BAD_REQUEST,
                "empty_completion",
                "upstream returned a completion with no choices, which it does when \
                 input plus max_tokens exceeds the model's context window — reduce \
                 either and retry",
            );
        }
        harvest(&state.metrics, model, gen_ms, &v);
    }
    (status, out, payload).into_response()
}

/// Pull every measurement a response carries about itself, in either protocol.
///
/// Content-blind throughout: counts, reasons and durations, never a byte of the
/// message. The stop reason matters more than it looks — `length`/`max_tokens`
/// means the answer was cut off at the output cap, which reads as a stupid model
/// until you can see it was truncated.
///
/// Called once per buffered response, and once per `data:` frame of a stream.
/// Anthropic splits its accounting over two frames — `message_start` nests usage
/// under `message`, `message_delta` nests the stop reason under `delta` — so both
/// nestings are checked, or a streamed Anthropic request records its output and
/// none of its input.
fn harvest(metrics: &crate::metrics::Metrics, model: &str, gen_ms: u64, v: &serde_json::Value) {
    let nested_usage = v.get("message").and_then(|m| m.get("usage"));
    if let Some(u) = v.get("usage").or(nested_usage) {
        let n = |k: &str| u.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
        // OpenAI names these prompt/completion; Anthropic names them
        // input/output. Same two numbers, so read whichever is present rather
        // than carrying the protocol down here.
        let (p, c) = match (n("prompt_tokens"), n("completion_tokens")) {
            (0, 0) => (n("input_tokens"), n("output_tokens")),
            pair => pair,
        };
        if p > 0 || c > 0 {
            metrics.record_tokens(model, p, c);
        }
        // A frame that reports no output tokens says nothing about speed;
        // recording it would average a real rate against a zero.
        if c > 0 {
            metrics.record_speed(model, c, gen_ms);
        }
        let reasoning = u
            .get("completion_tokens_details")
            .and_then(|d| d.get("reasoning_tokens"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        if reasoning > 0 {
            metrics.record_extras(model, 0, reasoning);
        }
    }
    // Anthropic states how a generation ended at the top level when buffered, and
    // inside `delta` when streamed. Tool calls are blocks within `content` rather
    // than a field beside the message.
    if let Some(reason) = v
        .get("stop_reason")
        .or_else(|| v.get("delta").and_then(|d| d.get("stop_reason")))
        .and_then(|r| r.as_str())
    {
        metrics.record_finish(model, reason);
    }
    if let Some(blocks) = v.get("content").and_then(|c| c.as_array()) {
        let calls = blocks
            .iter()
            .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
            .count() as u64;
        if calls > 0 {
            metrics.record_extras(model, calls, 0);
        }
    }
    if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
        for ch in choices {
            if let Some(r) = ch.get("finish_reason").and_then(|r| r.as_str()) {
                metrics.record_finish(model, r);
            }
            let calls = ch
                .get("message")
                .and_then(|m| m.get("tool_calls"))
                .and_then(|t| t.as_array())
                .map(|a| a.len() as u64)
                .unwrap_or(0);
            if calls > 0 {
                metrics.record_extras(model, calls, 0);
            }
        }
    }
}

// --- Streaming path ----------------------------------------------------------

/// True if the client asked for a streamed response (`"stream": true`).
fn wants_stream(body: &serde_json::Value) -> bool {
    body.get("stream")
        .and_then(serde_json::Value::as_bool)
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
#[allow(clippy::too_many_arguments)]
async fn acquire_for_heartbeating(
    state: &Arc<AppState>,
    provider: Option<&str>,
    excluded: &[usize],
    session: Option<u64>,
    wire: Protocol,
    deadline: Option<Instant>,
    tx: &Tx,
) -> Result<Option<Permit>, ()> {
    let acq = state
        .dispatch
        .acquire_for(provider, excluded, session, Some(wire));
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
    requested: Option<String>,
    session: Option<u64>,
    wire: Protocol,
    // Held for the life of the stream so `max_inflight` bounds live streams too,
    // not just the brief window before the response is committed.
    _inflight: InflightGuard,
    tx: Tx,
) {
    let t0 = Instant::now();
    let model = requested.clone().unwrap_or_else(|| "unknown".to_string());
    // Immediate heartbeat so the client sees the stream is live right away.
    if tx.send(heartbeat_frame()).await.is_err() {
        return;
    }
    let pool_len = state.pool.read().unwrap().len();
    let offering = state.catalog.providers_offering(&model);
    let plan = resolve_plan(requested.as_deref(), &aliases, pool_len, &offering);
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
            state.metrics.record_event("deadline");
            record(&state, &client, &model, &path_query, "504", None, t0);
            let _ = tx.send(sse_error("deadline_exceeded")).await;
            return;
        };
        let queued_at = Instant::now();
        let permit = match acquire_for_heartbeating(
            &state,
            step.provider.as_deref(),
            &excluded,
            session,
            wire,
            deadline,
            &tx,
        )
        .await
        {
            Ok(Some(p)) => {
                state
                    .metrics
                    .record_queue_wait(queued_at.elapsed().as_millis() as u64);
                p
            }
            Ok(None) => continue,
            Err(()) => {
                state.metrics.record_event("deadline");
                record(&state, &client, &model, &path_query, "504", None, t0);
                let _ = tx.send(sse_error("deadline_exceeded")).await;
                return;
            }
        };
        // The send time comes back with the response so time-to-first-token is
        // measured from the attempt that actually produced it, not from the
        // first attempt of a step that retried.
        let (sent, upstream_at) = loop {
            let attempt_at = Instant::now();
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
                    state.metrics.record_event("deadline");
                    record(&state, &client, &model, &path_query, "504", None, t0);
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
            break (sent, attempt_at);
        };
        match sent {
            Ok(resp) => {
                if is_retryable(resp.status().as_u16()) {
                    bench_lane(
                        &state,
                        permit.lane_idx,
                        step_model,
                        resp.status().as_u16(),
                        resp.headers(),
                    );
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
                record(
                    &state,
                    &client,
                    &model,
                    &path_query,
                    "200",
                    Some(permit.lane_idx),
                    t0,
                );
                state.metrics.record_lane(&permit.provider);
                stream_body(&state, &model, upstream_at, resp, deadline, &tx).await;
                return;
            }
            Err(_) => {
                if !is_last {
                    excluded.push(permit.lane_idx);
                    continue;
                }
                record(
                    &state,
                    &client,
                    &model,
                    &path_query,
                    "502",
                    Some(permit.lane_idx),
                    t0,
                );
                let _ = tx.send(sse_error("upstream_error")).await;
                return;
            }
        }
    }
    record(&state, &client, &model, &path_query, "503", None, t0);
    let _ = tx.send(sse_error("no_capacity")).await;
}

/// Forward the upstream response body chunk-by-chunk into the client stream,
/// measuring it on the way past.
///
/// This is where time-to-first-token is a real measurement rather than an
/// approximation: the gap to the first chunk is exactly what a user experiences
/// as "did it hear me". Everything after that is generation speed. The final
/// SSE frame carries usage when `stream_options` was accepted, which is what
/// the injection exists to obtain.
async fn stream_body(
    state: &Arc<AppState>,
    model: &str,
    sent_at: Instant,
    resp: reqwest::Response,
    deadline: Option<Instant>,
    tx: &Tx,
) {
    use futures_util::StreamExt;
    let mut stream = Box::pin(resp.bytes_stream());
    let mut first_seen: Option<Instant> = None;
    let mut tail = String::new();
    loop {
        match with_deadline(deadline, stream.next()).await {
            None => {
                state.metrics.record_event("deadline");
                let _ = tx.send(sse_error("deadline_exceeded")).await;
                return;
            }
            Some(None) => {
                // Usage and finish_reason arrive in the last frames, so they are
                // only readable once the stream has ended.
                if let Some(started) = first_seen {
                    let gen_ms = started.elapsed().as_millis() as u64;
                    for line in tail.lines() {
                        let Some(rest) = line.strip_prefix("data: ") else {
                            continue;
                        };
                        if rest.trim() == "[DONE]" {
                            continue;
                        }
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(rest) {
                            harvest(&state.metrics, model, gen_ms, &v);
                        }
                    }
                }
                return;
            }
            Some(Some(Ok(chunk))) => {
                if first_seen.is_none() {
                    first_seen = Some(Instant::now());
                    state
                        .metrics
                        .record_ttft(model, sent_at.elapsed().as_millis() as u64);
                }
                // Keep only a trailing window: usage rides in the last frames and
                // buffering a whole generation to find it would defeat streaming.
                tail.push_str(&String::from_utf8_lossy(&chunk));
                if tail.len() > 8192 {
                    tail = tail.split_off(tail.len() - 4096);
                }
                if tx.send(Ok(chunk)).await.is_err() {
                    state.metrics.record_event("client_disconnect");
                    return; // client hung up
                }
            }
            Some(Some(Err(_))) => {
                state.metrics.record_event("stream_error");
                let _ = tx.send(sse_error("stream_error")).await;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::any;

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
    /// Observed in production: NVIDIA answered 529 "Service temporarily
    /// overloaded" and it reached the client verbatim, because 529 is not in any
    /// RFC and was not in the list. It means retry, so it must be retried.
    /// Everything an OpenAI-shaped answer reports about itself has to reach the
    /// metrics. Verified here rather than against a provider, because the
    /// provider being unavailable is exactly when these numbers matter and
    /// exactly when a live check cannot run.
    #[test]
    fn harvest_reads_usage_finish_reason_and_tool_calls() {
        let metrics = crate::metrics::Metrics::default();
        let body = serde_json::json!({
            "choices": [{
                "finish_reason": "length",
                "message": { "tool_calls": [{"id": "a"}, {"id": "b"}] }
            }],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 250,
                "completion_tokens_details": { "reasoning_tokens": 40 }
            }
        });
        // 250 completion tokens in 5s = 50/sec.
        harvest(&metrics, "m", 5000, &body);
        metrics.record_request("c", "m", "200");

        let stats = metrics.stats();
        let m = &stats.models[0];
        assert_eq!(m.completion_tokens, 250, "tokens");
        assert_eq!(m.avg_tokens_per_sec, 50, "speed");
        assert_eq!(m.truncated, 1, "finish_reason=length is truncation");
        assert_eq!(m.tool_calls, 2, "tool calls");
        assert_eq!(m.reasoning_tokens, 40, "reasoning tokens");
    }

    #[test]
    fn a_success_carrying_no_choices_is_not_a_success() {
        // NVIDIA answers an over-long request with 200 OK and this exact shape:
        // no choices, null usage, no error anywhere. Verified against the
        // provider directly, with the proxy out of the path.
        let overflowed = json(
            r#"{"id":"","choices":[],"created":0,"model":"","object":"chat.completion","usage":null}"#,
        );
        assert!(
            is_empty_completion(&overflowed),
            "an empty choices array is never a valid completion"
        );

        // A real answer, a streaming chunk, and an unrelated 200 must all pass.
        assert!(!is_empty_completion(&json(
            r#"{"object":"chat.completion","choices":[{"message":{"content":"hi"}}]}"#
        )));
        assert!(!is_empty_completion(&json(
            r#"{"object":"chat.completion.chunk","choices":[]}"#
        )));
        assert!(!is_empty_completion(&json(r#"{"data":[{"id":"m"}]}"#)));
    }

    #[test]
    fn a_context_ceiling_is_learned_from_the_providers_complaint() {
        // The exact body NVIDIA returns, captured from a real overflow.
        let nvidia = r#"{"message":"This model's maximum context length is 202752 tokens. However, your messages resulted in 249928 tokens. Please reduce the length of the messages.","type":"Bad Request","code":400}"#;
        assert_eq!(parse_context_limit(nvidia), Some(202_752));

        // OpenAI phrases the same complaint with a comma and lowercase however.
        let openai = "This model's maximum context length is 8192 tokens, however you requested 9000 tokens.";
        assert_eq!(parse_context_limit(openai), Some(8192));

        // Anything else must teach us nothing rather than a wrong number.
        assert_eq!(
            parse_context_limit(r#"{"message":"invalid api key"}"#),
            None
        );
        assert_eq!(parse_context_limit("maximum context length is soon"), None);
        assert_eq!(parse_context_limit(""), None);
    }

    #[test]
    fn overload_and_timeout_statuses_are_retried() {
        for status in [408, 429, 500, 502, 503, 504, 529] {
            assert!(is_retryable(status), "{status} should be retried");
        }
        for status in [200, 400, 401, 403, 404, 422] {
            assert!(!is_retryable(status), "{status} must not be retried");
        }
    }

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

    fn providers_of(plan: &[PlanStep]) -> Vec<Option<&str>> {
        plan.iter().map(|s| s.provider.as_deref()).collect()
    }

    #[test]
    fn a_plain_model_prefers_providers_that_actually_list_it() {
        let plan = resolve_plan(Some("m"), &[], 4, &["together".to_string()]);
        assert_eq!(providers_of(&plan)[0], Some("together"));
        assert!(
            plan.iter().any(|s| s.provider.is_none()),
            "a stale catalog must not strand the request"
        );
    }

    #[test]
    fn with_no_catalog_knowledge_every_step_is_unrestricted() {
        let plan = resolve_plan(Some("m"), &[], 3, &[]);
        assert_eq!(providers_of(&plan), vec![None, None, None]);
    }

    /// An alias is an explicit instruction about where to route; catalog contents
    /// are an inference. The explicit one wins.
    #[test]
    fn an_alias_still_overrides_catalog_preference() {
        let alias = Alias {
            name: "virtual".into(),
            targets: vec![crate::config::AliasTarget {
                provider: "chosen".into(),
                model: "real".into(),
            }],
        };
        let plan = resolve_plan(Some("virtual"), &[alias], 4, &["other".to_string()]);
        assert_eq!(providers_of(&plan), vec![Some("chosen")]);
    }

    fn json(raw: &str) -> serde_json::Value {
        serde_json::from_str(raw).expect("test fixture is valid json")
    }

    #[test]
    fn usage_injection_adds_include_usage() {
        let out = inject_usage(&json(r#"{"model":"m","stream":true}"#)).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["stream_options"]["include_usage"], true);
        assert_eq!(v["model"], "m", "the rest of the body is untouched");
    }

    /// A client that set `stream_options` itself meant it. Our token accounting
    /// is not a good enough reason to overwrite what they asked for.
    #[test]
    fn usage_injection_leaves_a_clients_own_stream_options_alone() {
        let body = json(r#"{"model":"m","stream_options":{"include_usage":false}}"#);
        assert!(inject_usage(&body).is_none());
    }

    #[test]
    fn usage_injection_declines_a_body_that_is_not_an_object() {
        assert!(inject_usage(&json("[1,2,3]")).is_none());
        assert!(inject_usage(&serde_json::Value::Null).is_none());
    }

    /// The parse happens once, at the edge. A body that isn't JSON yields no
    /// model, no session and no stream flag, and is forwarded untouched.
    #[test]
    fn a_non_json_body_is_simply_opaque() {
        let parsed: Option<serde_json::Value> = serde_json::from_slice(b"not json").ok();
        assert!(parsed.is_none());
        assert!(parsed.as_ref().and_then(requested_model).is_none());
        assert!(parsed.as_ref().and_then(session_key).is_none());
        assert!(!parsed.as_ref().is_some_and(wants_stream));
    }

    // --- properties over untrusted input ---------------------------------
    //
    // These parsers read bytes chosen by someone else — a client's path and
    // body, an upstream's headers. The property that matters most is the dull
    // one: whatever arrives, they return a value and never panic. A panic in an
    // axum handler kills that request, and a panic reachable by any caller is a
    // denial of service with no authentication needed.

    proptest::proptest! {
        #[test]
        fn normalize_path_never_panics_and_stays_a_path(raw in ".*") {
            let out = normalize_path(&raw);
            // Collapsing only ever removes whole "/v1" segments, so the result
            // cannot grow and cannot invent a prefix the caller never sent.
            proptest::prop_assert!(out.len() <= raw.len());
            if raw.starts_with('/') {
                proptest::prop_assert!(out.starts_with('/'));
            }
            // Idempotent: normalizing an already-normal path changes nothing.
            proptest::prop_assert_eq!(normalize_path(&out), out.clone());
        }

        #[test]
        fn normalize_path_leaves_no_doubled_prefix(depth in 0usize..12, tail in "[a-z/]{0,20}") {
            let raw = format!("{}{tail}", "/v1".repeat(depth));
            let out = normalize_path(&raw);
            proptest::prop_assert!(!out.starts_with("/v1/v1/"), "left a doubled prefix: {}", out);
        }

        #[test]
        fn retry_after_never_panics_and_is_always_clamped(raw in ".*") {
            let mut h = HeaderMap::new();
            if let Ok(v) = HeaderValue::from_str(&raw) {
                h.insert(header::RETRY_AFTER, v);
            }
            if let Some(d) = retry_after(&h) {
                proptest::prop_assert!(d <= MAX_RETRY_AFTER, "unclamped: {:?}", d);
            }
        }

        /// A body is attacker-controlled and arbitrary bytes are not JSON. Every
        /// helper has to shrug rather than fall over.
        #[test]
        fn body_helpers_survive_arbitrary_bytes(raw in proptest::collection::vec(any::<u8>(), 0..512)) {
            let parsed: Option<serde_json::Value> = serde_json::from_slice(&raw).ok();
            let _ = parsed.as_ref().and_then(requested_model);
            let _ = parsed.as_ref().and_then(session_key);
            let _ = parsed.as_ref().is_some_and(wants_stream);
            let _ = parsed.as_ref().and_then(inject_usage);
            let _ = rewrite_model(&Bytes::from(raw), Some("m"));
        }

        /// The same conversation must key identically however the tail grows —
        /// the property the whole affinity design rests on.
        #[test]
        fn session_key_ignores_everything_after_the_opening(
            head in "[a-z ]{1,40}", tail in proptest::collection::vec("[a-z ]{0,20}", 0..8)
        ) {
            let opening = serde_json::json!([
                {"role": "system", "content": head.clone()},
                {"role": "user", "content": "hello"}
            ]);
            let mut grown = opening.as_array().unwrap().clone();
            for (i, t) in tail.iter().enumerate() {
                grown.push(serde_json::json!({
                    "role": if i % 2 == 0 { "assistant" } else { "user" }, "content": t
                }));
            }
            let first = session_key(&serde_json::json!({"model": "m", "messages": opening}));
            let later = session_key(&serde_json::json!({"model": "m", "messages": grown}));
            proptest::prop_assert_eq!(first, later);
        }
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
