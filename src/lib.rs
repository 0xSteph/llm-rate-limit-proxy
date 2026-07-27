pub mod auth;
pub mod config;
pub mod dispatch;
pub mod metrics;
pub mod pool;
pub mod proxy;
pub mod setup;

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::Router;

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
    /// Content-blind request metrics (counts by client/model/status).
    pub metrics: metrics::Metrics,
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
        "<!doctype html><meta charset=utf-8><title>Sluice</title><h1>Sluice</h1>",
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
        pool,
        http,
        provider_window,
        metrics: metrics::Metrics::default(),
    });

    let protected = Router::new()
        .route("/", get(root))
        .route("/dash", get(root))
        .route("/metrics", get(metrics_handler))
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
