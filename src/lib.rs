pub mod auth;
pub mod cache;
pub mod config;
pub mod dispatch;
pub mod governor;
pub mod history;
pub mod metrics;
pub mod models;
pub mod pool;
pub mod proxy;
pub mod settings;
pub mod setup;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};

/// Shared application state. One `Arc<AppState>` is handed to every request.
pub struct AppState {
    /// The persisted source of truth; its mutex doubles as the save-mutex.
    pub store: Mutex<config::StoredConfig>,
    /// Where the config store lives (DATA_DIR).
    pub data_dir: std::path::PathBuf,
    /// True until a superuser exists: the wizard is open, everything else closed.
    pub setup_required: AtomicBool,
    /// Session + credential machinery for the operator surface.
    pub admin: auth::Admin,
    /// Unix time this process started (dashboard uptime).
    pub started: u64,
    /// The live key pool; settings/setup swap it in place without a restart.
    pub pool: pool::PoolHandle,
    /// Grants rate slots across the pool in FIFO order.
    pub dispatch: dispatch::Dispatcher,
    /// Shared upstream HTTP client (connection pooling, no overall timeout).
    pub http: reqwest::Client,
    /// The provider's real rate window; the pool enforces over this plus a margin.
    pub provider_window: Duration,
    /// Requests currently in flight, bounded by `settings.max_inflight`.
    pub inflight: Arc<AtomicUsize>,
    /// Per-model concurrency gate for provider-side pressure that key failover
    /// cannot relieve.
    pub governor: Arc<governor::Governor>,
    /// Cached per-provider model catalogs behind the merged `/v1/models`.
    pub catalog: Arc<models::Catalog>,
    /// Models observed to reject `stream_options`, so we stop adding it for them.
    pub no_inject: Mutex<std::collections::HashSet<String>>,
    /// Content-blind request metrics (counts by client/model/status).
    pub metrics: metrics::Metrics,
    /// Persisted 5-minute snapshots for range views.
    pub history: Arc<history::History>,
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        state.metrics.render(),
    )
}

async fn api_history(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Vec<history::Snapshot>> {
    let now = unix_now();
    let get = |k: &str, d: u64| q.get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
    let (from, to) = (get("from", now.saturating_sub(86_400)), get("to", now));
    Json(state.history.range(from, to, 500))
}

async fn api_stats(State(state): State<Arc<AppState>>) -> Json<metrics::Stats> {
    Json(state.metrics.stats())
}

/// Models currently held back by provider-side pressure. Separate from rate
/// capacity on purpose: these requests never reach the rate limiter, so rate
/// figures read idle while they wait. An operator seeing "0% capacity used" and
/// a stalled agent needs this to be visible somewhere.
async fn api_pressure(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "pressured": state.governor.pressured(std::time::Instant::now()),
    }))
}

/// Live bootstrap config for the dashboard (pool shape, capacity, uptime).
async fn dash_config(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let pool = state.pool.read().unwrap().clone();
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "lanes": pool.len(),
        "capacity_rpm": pool.capacity_rpm(),
        "rpms": pool.rpms(),
        "started": state.started,
        "provider_window_secs": state.provider_window.as_secs(),
    }))
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Add hardening headers to every response. `default-src 'none'` plus explicit
/// allowances for the dashboard's own inline assets; `connect-src 'self'` stops an
/// injected element from exfiltrating to another origin.
async fn security_headers(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    use axum::http::HeaderValue;
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
             script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; \
             base-uri 'none'; form-action 'self'",
        ),
    );
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    resp
}

async fn root() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("dashboard.html"),
    )
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

/// `sluice --health`: probe our own /health endpoint and exit 0/1. Exists because
/// the scratch container image has no shell or curl for HEALTHCHECK.
fn health_probe() -> ! {
    use std::io::{Read, Write};
    let port = env_or("PORT", "8000");
    let ok = (|| -> std::io::Result<bool> {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port.parse().unwrap_or(8000)))?;
        s.set_read_timeout(Some(Duration::from_secs(2)))?;
        s.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut buf = [0u8; 32];
        let n = s.read(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf[..n]).contains("200"))
    })()
    .unwrap_or(false);
    std::process::exit(if ok { 0 } else { 1 });
}

#[tokio::main]
pub async fn run() {
    if std::env::args().any(|a| a == "--health") {
        health_probe();
    }

    let trust_proxy = env_or("TRUST_PROXY", "false") == "true";

    // The config store holds credentials, so its home must exist and be writable
    // before anything else — an unwritable DATA_DIR is a hard boot error.
    let data_dir = std::path::PathBuf::from(env_or("DATA_DIR", "data"));
    let writable = std::fs::create_dir_all(&data_dir).and_then(|()| {
        let probe = data_dir.join(".write-probe");
        std::fs::write(&probe, b"ok")?;
        std::fs::remove_file(&probe)
    });
    if let Err(e) = writable {
        eprintln!(
            "sluice cannot start: DATA_DIR {} is not writable ({e})",
            data_dir.display()
        );
        std::process::exit(1);
    }

    let stored = match config::load(&data_dir) {
        Ok(Some(sc)) => sc,
        Ok(None) => config::StoredConfig::default(),
        Err(e) => {
            eprintln!("sluice cannot start: {e}");
            std::process::exit(1);
        }
    };
    let setup_required = stored.superuser().is_none();
    let models_ttl = stored.settings.models_ttl_secs;

    let history = Arc::new(history::History::load(
        Some(data_dir.join("history.jsonl")),
        stored.settings.history_days,
    ));

    // Undocumented test knob; 60s is the contract. Lets pacing tests run fast.
    let provider_window = env_or("SLUICE_PROVIDER_WINDOW_MS", "")
        .parse::<u64>()
        .map(Duration::from_millis)
        .unwrap_or(pool::PROVIDER_WINDOW);
    let pool: pool::PoolHandle = Arc::new(RwLock::new(Arc::new(pool::Pool::for_provider_window(
        pool::lane_specs(&stored),
        provider_window,
    ))));
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        // No overall timeout: generations can stream for a long time.
        .build()
        .expect("build HTTP client");

    let state = Arc::new(AppState {
        store: Mutex::new(stored),
        data_dir,
        setup_required: AtomicBool::new(setup_required),
        admin: auth::Admin::new(trust_proxy),
        started: unix_now(),
        dispatch: dispatch::Dispatcher::new(pool.clone()),
        inflight: Arc::new(AtomicUsize::new(0)),
        governor: Arc::new(governor::Governor::default()),
        catalog: Arc::new(models::Catalog::new(Duration::from_secs(models_ttl))),
        no_inject: Mutex::new(std::collections::HashSet::new()),
        pool,
        http,
        provider_window,
        metrics: metrics::Metrics::default(),
        history,
    });

    // Snapshot the request total on an interval so range views have trend data.
    {
        let history = state.history.clone();
        let sampled = state.clone();
        let sample_secs = env_or(
            "SLUICE_HISTORY_SAMPLE_SECS",
            &history::SAMPLE_SECS.to_string(),
        )
        .parse::<u64>()
        .unwrap_or(history::SAMPLE_SECS)
        .max(1);
        tokio::spawn(async move {
            loop {
                history.append(unix_now(), sampled.metrics.total());
                tokio::time::sleep(Duration::from_secs(sample_secs)).await;
            }
        });
    }

    let protected = Router::new()
        .route("/", get(root))
        .route("/dash", get(root))
        .route("/metrics", get(metrics_handler))
        .route("/api/history", get(api_history))
        .route("/api/stats", get(api_stats))
        .route("/api/pressure", get(api_pressure))
        .route("/api/settings", get(settings::view))
        .route("/api/settings/providers", post(settings::providers))
        .route("/api/settings/provider-keys", post(settings::provider_keys))
        .route("/api/settings/aliases", post(settings::aliases))
        .route("/api/settings/clients", post(settings::clients))
        .route("/api/settings/limits", post(settings::limits))
        .route("/api/settings/users", post(settings::users))
        .route("/dash/config.json", get(dash_config))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ));

    let app = Router::new()
        .merge(protected)
        .route("/health", get(|| async { "ok" }))
        .route("/login", get(auth::login_page).post(auth::login_submit))
        .route("/logout", post(auth::logout))
        .route("/setup", get(setup::setup_page).post(setup::setup_submit))
        .route("/v1/{*path}", any(proxy::handle))
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state);

    let host = env_or("HOST", "0.0.0.0");
    let port: u16 = env_or("PORT", "8000")
        .parse()
        .expect("PORT must be a number");
    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind listener");
    println!("sluice v{} listening on {addr}", env!("CARGO_PKG_VERSION"));
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server");
}
