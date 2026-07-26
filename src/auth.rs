//! Credential logic and the operator auth surface: password hashing, signed session
//! tokens, client API keys, the `require_session` guard, and login/logout. Kept in
//! one place so the security posture is auditable from a single file.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::ClientKey;
use crate::AppState;

const PBKDF2_ROUNDS: u32 = 600_000;

/// Session lifetime and the cookie it rides in.
pub const SESSION_TTL: u64 = 12 * 3600;
const SESSION_COOKIE: &str = "sluice_session";

/// Failed-login throttle: after this many failures inside the window, further
/// attempts are rejected until the window elapses.
const MAX_LOGIN_FAILS: u32 = 5;
const LOGIN_WINDOW: Duration = Duration::from_secs(60);

type HmacSha256 = Hmac<Sha256>;

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn b64d(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let digest = h.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

// --- Passwords ---------------------------------------------------------------

/// Hash a password with PBKDF2-HMAC-SHA256 (600k iterations, random 16-byte salt),
/// stored as `pbkdf2$sha256$<rounds>$<b64salt>$<b64hash>`.
pub fn hash_password(pw: &str) -> String {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).expect("system RNG");
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pw.as_bytes(), &salt, PBKDF2_ROUNDS, &mut out);
    format!("pbkdf2$sha256${PBKDF2_ROUNDS}${}${}", b64(&salt), b64(&out))
}

/// Constant-time verification of a password against a stored hash.
pub fn verify_password(pw: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 5 || parts[0] != "pbkdf2" || parts[1] != "sha256" {
        return false;
    }
    let Ok(rounds) = parts[2].parse::<u32>() else {
        return false;
    };
    let (Some(salt), Some(expected)) = (b64d(parts[3]), b64d(parts[4])) else {
        return false;
    };
    let mut out = vec![0u8; expected.len()];
    pbkdf2_hmac::<Sha256>(pw.as_bytes(), &salt, rounds, &mut out);
    ct_eq(&out, &expected)
}

// --- Sessions ----------------------------------------------------------------

struct LoginThrottle {
    fails: u32,
    window_start: Instant,
}

/// Session machinery: an HMAC signing key (random per boot, so sessions reset on
/// restart), the `trust_proxy` flag that marks cookies `Secure`, and the shared
/// failed-login throttle.
pub struct Admin {
    key: [u8; 32],
    trust_proxy: bool,
    throttle: Mutex<LoginThrottle>,
}

impl Admin {
    pub fn new(trust_proxy: bool) -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("system RNG");
        Self {
            key,
            trust_proxy,
            throttle: Mutex::new(LoginThrottle {
                fails: 0,
                window_start: Instant::now(),
            }),
        }
    }

    /// Whether session cookies should carry the `Secure` attribute.
    pub fn secure_cookies(&self) -> bool {
        self.trust_proxy
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn sign_token(&self, username: &str, expiry: u64) -> String {
        let payload = format!("{username}|{expiry}");
        let sig = hmac_sha256(&self.key, payload.as_bytes());
        format!("{}.{}", b64(payload.as_bytes()), b64(&sig))
    }

    /// Mint a session token valid for `ttl_secs` seconds.
    pub fn mint(&self, username: &str, ttl_secs: u64) -> String {
        self.sign_token(username, Self::now() + ttl_secs)
    }

    /// Return the username iff the token's signature is valid and it hasn't expired.
    pub fn verify(&self, token: &str) -> Option<String> {
        let (payload_b64, sig_b64) = token.split_once('.')?;
        let payload = b64d(payload_b64)?;
        let sig = b64d(sig_b64)?;
        let expected = hmac_sha256(&self.key, &payload);
        if !ct_eq(&sig, &expected) {
            return None;
        }
        let payload = String::from_utf8(payload).ok()?;
        let (username, expiry) = payload.rsplit_once('|')?;
        if Self::now() >= expiry.parse::<u64>().ok()? {
            return None;
        }
        Some(username.to_string())
    }

    /// True while the failure window is saturated — reject new attempts.
    pub fn is_throttled(&self) -> bool {
        let t = self.throttle.lock().unwrap();
        t.fails >= MAX_LOGIN_FAILS && t.window_start.elapsed() < LOGIN_WINDOW
    }

    fn record_login_failure(&self) {
        let mut t = self.throttle.lock().unwrap();
        if t.window_start.elapsed() >= LOGIN_WINDOW {
            t.fails = 0;
            t.window_start = Instant::now();
        }
        t.fails += 1;
    }

    fn reset_login_failures(&self) {
        self.throttle.lock().unwrap().fails = 0;
    }
}

fn session_cookie(token: &str, secure: bool) -> String {
    let mut c = format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}"
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn clear_cookie(secure: bool) -> String {
    let mut c = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn session_from_cookies(header: Option<&str>) -> Option<String> {
    let prefix = format!("{SESSION_COOKIE}=");
    header?
        .split(';')
        .find_map(|p| p.trim().strip_prefix(&prefix).map(str::to_string))
}

// --- Operator auth surface ---------------------------------------------------

/// Guard for the dashboard surface. Pre-setup, everything routes to the wizard;
/// after setup, an unauthenticated request is bounced to the login page.
pub async fn require_session(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    if state.setup_required.load(Ordering::Relaxed) {
        return Redirect::to("/setup").into_response();
    }
    let cookie = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok());
    let authed = session_from_cookies(cookie)
        .and_then(|t| state.admin.verify(&t))
        .is_some();
    if authed {
        next.run(req).await
    } else {
        Redirect::to("/login").into_response()
    }
}

const LOGIN_HTML: &str = r#"<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>Sluice — Sign in</title>
<h1>Sluice</h1>
<form method=post action=/login>
  <p><input name=username placeholder=Username autofocus></p>
  <p><input name=password type=password placeholder=Password></p>
  <p><button type=submit>Sign in</button></p>
</form>"#;

pub async fn login_page() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        LOGIN_HTML,
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn login_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    if state.admin.is_throttled() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many attempts, try again shortly",
        )
            .into_response();
    }
    let ok = {
        let store = state.store.lock().unwrap();
        store
            .users
            .iter()
            .find(|u| u.username == form.username)
            .map(|u| verify_password(&form.password, &u.pw_hash))
            .unwrap_or(false)
    };
    if !ok {
        state.admin.record_login_failure();
        return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    }
    state.admin.reset_login_failures();
    let token = state.admin.mint(&form.username, SESSION_TTL);
    let cookie = session_cookie(&token, state.admin.secure_cookies());
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, "/".to_string()),
        ],
        "",
    )
        .into_response()
}

pub async fn logout(State(state): State<Arc<AppState>>) -> Response {
    let cookie = clear_cookie(state.admin.secure_cookies());
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, "/login".to_string()),
        ],
        "",
    )
        .into_response()
}

// --- Client API keys ---------------------------------------------------------

/// Mint a client API key. Returns the one-time secret (`slk_…`) and the record to
/// persist (digest + last-4 only — the secret itself is never stored).
pub fn new_client_key(label: &str, owner: &str) -> (String, ClientKey) {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("system RNG");
    let secret = format!("slk_{}", b64(&bytes));
    let last4 = secret[secret.len() - 4..].to_string();
    let record = ClientKey {
        label: label.to_string(),
        digest: sha256_hex(secret.as_bytes()),
        last4,
        owner: owner.to_string(),
    };
    (secret, record)
}

/// Return the matching key's label iff `secret` hashes to a stored digest.
pub fn verify_client_key(secret: &str, keys: &[ClientKey]) -> Option<String> {
    let digest = sha256_hex(secret.as_bytes());
    keys.iter()
        .find(|k| ct_eq(digest.as_bytes(), k.digest.as_bytes()))
        .map(|k| k.label.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pw_hash_then_verify_true() {
        let h = hash_password("hunter2");
        assert!(verify_password("hunter2", &h));
    }

    #[test]
    fn pw_wrong_password_false() {
        let h = hash_password("hunter2");
        assert!(!verify_password("nope", &h));
    }

    #[test]
    fn pw_distinct_salts_distinct_hashes() {
        assert_ne!(hash_password("x"), hash_password("x"));
    }

    #[test]
    fn pw_garbage_hash_rejected() {
        assert!(!verify_password("x", "not-a-hash"));
    }

    #[test]
    fn session_mint_then_verify_roundtrips() {
        let a = Admin::new(false);
        let t = a.mint("alice", 3600);
        assert_eq!(a.verify(&t).as_deref(), Some("alice"));
    }

    #[test]
    fn session_forged_payload_rejected() {
        let a = Admin::new(false);
        let real = a.mint("alice", 3600);
        let (_, sig) = real.split_once('.').unwrap();
        // Keep alice's signature but swap in a forged identity/expiry.
        let forged = format!("{}.{sig}", b64(b"mallory|9999999999"));
        assert!(a.verify(&forged).is_none());
    }

    #[test]
    fn session_expired_token_rejected() {
        let a = Admin::new(false);
        let expired = a.sign_token("alice", Admin::now().saturating_sub(10));
        assert!(a.verify(&expired).is_none());
    }

    #[test]
    fn session_foreign_key_rejected() {
        let (a, b) = (Admin::new(false), Admin::new(false));
        let t = a.mint("alice", 3600);
        assert!(b.verify(&t).is_none());
    }

    #[test]
    fn cookie_parse_finds_session() {
        assert_eq!(
            session_from_cookies(Some("foo=1; sluice_session=abc.def; bar=2")).as_deref(),
            Some("abc.def")
        );
        assert!(session_from_cookies(Some("foo=1")).is_none());
        assert!(session_from_cookies(None).is_none());
    }

    #[test]
    fn throttle_trips_after_max_fails() {
        let a = Admin::new(false);
        for _ in 0..MAX_LOGIN_FAILS {
            assert!(!a.is_throttled());
            a.record_login_failure();
        }
        assert!(a.is_throttled());
        a.reset_login_failures();
        assert!(!a.is_throttled());
    }

    #[test]
    fn client_key_mint_and_verify() {
        let (secret, rec) = new_client_key("bench", "admin");
        assert!(secret.starts_with("slk_"));
        assert_eq!(verify_client_key(&secret, &[rec]).as_deref(), Some("bench"));
    }

    #[test]
    fn client_key_unknown_rejected() {
        assert!(verify_client_key("slk_bogus", &[]).is_none());
        let (_, rec) = new_client_key("a", "admin");
        assert!(verify_client_key("slk_wrong", &[rec]).is_none());
    }
}
