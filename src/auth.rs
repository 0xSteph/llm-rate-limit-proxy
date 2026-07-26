//! Credential logic: password hashing, signed session tokens, and client API keys.
//! Kept free of HTTP so it can be unit-tested in isolation; the middleware and
//! login/logout handlers that use it are wired up in `lib.rs`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::ClientKey;

const PBKDF2_ROUNDS: u32 = 600_000;

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

/// Session machinery: an HMAC signing key (random per boot, so sessions reset on
/// restart) plus the `trust_proxy` flag that marks cookies `Secure` behind TLS.
pub struct Admin {
    key: [u8; 32],
    trust_proxy: bool,
}

impl Admin {
    pub fn new(trust_proxy: bool) -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("system RNG");
        Self { key, trust_proxy }
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
