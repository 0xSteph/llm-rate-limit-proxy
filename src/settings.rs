//! Runtime settings: change provider keys, client keys, and limits while the
//! proxy is serving, with no restart and no hand-editing of `config.json`.
//!
//! Every mutation follows the same shape — validate, persist, then swap in a
//! rebuilt pool that carries each surviving key's spent budget across. Skipping
//! the carryover would hand every key a fresh rate window on save, and a save is
//! exactly what someone does while they are at capacity and adding keys.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::{auth, config, pool, AppState};

fn bad_request(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": {"message": message, "code": "invalid_request"}})),
    )
        .into_response()
}

/// Persist the store and swap in a pool rebuilt from it.
///
/// The store lock is released before the pool swap so a save never holds two
/// locks at once, and the rebuild carries rate state so this is safe to call
/// while requests are in flight.
fn apply(state: &Arc<AppState>) -> Result<(), String> {
    let (specs, snapshot) = {
        let store = state.store.lock().unwrap();
        (pool::lane_specs(&store), store.clone())
    };
    config::save(&state.data_dir, &snapshot)?;
    let rebuilt = {
        let current = state.pool.read().unwrap().clone();
        current.rebuild(specs)
    };
    *state.pool.write().unwrap() = Arc::new(rebuilt);
    Ok(())
}

/// The operator's view of current configuration.
///
/// Provider keys are returned as last-4 only. They are stored in full because
/// they have to be sent upstream, but nothing needs to render them back, and a
/// settings page that displays live credentials is a screenshot away from
/// leaking them.
pub async fn view(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let store = state.store.lock().unwrap();
    Json(json!({
        "providers": store.providers.iter().map(|p| json!({
            "name": p.name,
            "base_url": p.base_url,
            "keys": p.keys.iter().map(|k| json!({
                "last4": last4(&k.key),
                "enabled": k.enabled,
                "rpm": k.rpm,
                "owner": k.owner,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "clients": store.clients.iter().map(|c| json!({
            "label": c.label,
            "last4": c.last4,
            "owner": c.owner,
        })).collect::<Vec<_>>(),
        "aliases": store.aliases,
        "settings": store.settings,
    }))
}

fn last4(secret: &str) -> String {
    secret
        .char_indices()
        .rev()
        .nth(3)
        .map(|(i, _)| secret[i..].to_string())
        .unwrap_or_else(|| secret.to_string())
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum KeyAction {
    Add {
        provider: String,
        key: String,
        rpm: Option<usize>,
    },
    Remove {
        provider: String,
        index: usize,
    },
    Update {
        provider: String,
        index: usize,
        enabled: Option<bool>,
        rpm: Option<usize>,
    },
}

/// Add, remove, enable/disable, or re-rate a provider key.
pub async fn provider_keys(
    State(state): State<Arc<AppState>>,
    Json(action): Json<KeyAction>,
) -> Response {
    {
        let mut store = state.store.lock().unwrap();
        let name = match &action {
            KeyAction::Add { provider, .. }
            | KeyAction::Remove { provider, .. }
            | KeyAction::Update { provider, .. } => provider.clone(),
        };
        let Some(p) = store.providers.iter_mut().find(|p| p.name == name) else {
            return bad_request(&format!("no provider named {name}"));
        };

        match action {
            KeyAction::Add { key, rpm, .. } => {
                let key = key.trim().to_string();
                if key.is_empty() {
                    return bad_request("key must not be empty");
                }
                if p.keys.iter().any(|k| k.key == key) {
                    return bad_request("that key is already in the pool");
                }
                let rpm = rpm.unwrap_or(40);
                if let Err(e) = check_rpm(rpm) {
                    return bad_request(&e);
                }
                p.keys.push(config::ProviderKey {
                    key,
                    enabled: true,
                    rpm,
                    owner: String::new(),
                });
            }
            KeyAction::Remove { index, .. } => {
                if index >= p.keys.len() {
                    return bad_request("no key at that position");
                }
                p.keys.remove(index);
            }
            KeyAction::Update {
                index,
                enabled,
                rpm,
                ..
            } => {
                let Some(k) = p.keys.get_mut(index) else {
                    return bad_request("no key at that position");
                };
                if let Some(rpm) = rpm {
                    if let Err(e) = check_rpm(rpm) {
                        return bad_request(&e);
                    }
                    k.rpm = rpm;
                }
                if let Some(enabled) = enabled {
                    k.enabled = enabled;
                }
            }
        }

        // Refuse to leave the proxy with nothing to serve on. Losing the last key
        // takes the data plane down, and doing it by accident from a settings page
        // — one stray disable — is far too easy.
        if pool::lane_specs(&store).is_empty() {
            return bad_request("that would leave no enabled keys and stop the proxy serving");
        }
    }

    match apply(&state) {
        Ok(()) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": {"message": e, "code": "save_failed"}})),
        )
            .into_response(),
    }
}

fn check_rpm(rpm: usize) -> Result<(), String> {
    match rpm {
        0 => Err("rpm must be at least 1; disable the key instead".into()),
        r if r > 10_000 => Err("rpm above 10000 is not a real provider limit".into()),
        _ => Ok(()),
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ClientAction {
    Mint { label: String },
    Revoke { last4: String },
}

/// Mint or revoke a client API key.
///
/// A minted secret is returned exactly once and never stored — only its digest
/// is kept — so there is no path, for an operator or an attacker with the config
/// file, to read an existing key back out.
pub async fn clients(
    State(state): State<Arc<AppState>>,
    Json(action): Json<ClientAction>,
) -> Response {
    let mut store = state.store.lock().unwrap();
    let minted = match action {
        ClientAction::Mint { label } => {
            let label = label.trim().to_string();
            if label.is_empty() {
                return bad_request("label must not be empty");
            }
            let (secret, record) = auth::new_client_key(&label, "");
            store.clients.push(record);
            Some(secret)
        }
        ClientAction::Revoke { last4 } => {
            let before = store.clients.len();
            store.clients.retain(|c| c.last4 != last4);
            if store.clients.len() == before {
                return bad_request("no client key ending in that");
            }
            None
        }
    };
    let snapshot = store.clone();
    drop(store);

    if let Err(e) = config::save(&state.data_dir, &snapshot) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": {"message": e, "code": "save_failed"}})),
        )
            .into_response();
    }
    match minted {
        Some(secret) => (
            StatusCode::OK,
            Json(json!({"ok": true, "key": secret,
                        "note": "shown once — it is stored only as a digest"})),
        )
            .into_response(),
        None => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct LimitsReq {
    pub max_inflight: Option<usize>,
    pub models_ttl_secs: Option<u64>,
    pub history_days: Option<u32>,
}

/// Update operational limits. `max_inflight` and `models_ttl_secs` are read per
/// request, so they take effect immediately.
pub async fn limits(State(state): State<Arc<AppState>>, Json(req): Json<LimitsReq>) -> Response {
    let snapshot = {
        let mut store = state.store.lock().unwrap();
        if let Some(v) = req.max_inflight {
            if v == 0 {
                return bad_request("max_inflight must be at least 1");
            }
            store.settings.max_inflight = v;
        }
        if let Some(v) = req.models_ttl_secs {
            store.settings.models_ttl_secs = v;
        }
        if let Some(v) = req.history_days {
            store.settings.history_days = v;
        }
        store.clone()
    };
    match config::save(&state.data_dir, &snapshot) {
        Ok(()) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": {"message": e, "code": "save_failed"}})),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last4_shows_only_the_tail() {
        assert_eq!(last4("nvapi-abcdefgh"), "efgh");
    }

    #[test]
    fn last4_of_a_short_secret_does_not_panic() {
        assert_eq!(last4("ab"), "ab");
    }

    #[test]
    fn rpm_zero_is_rejected_in_favour_of_disabling() {
        assert!(check_rpm(0).is_err());
        assert!(check_rpm(1).is_ok());
        assert!(check_rpm(40).is_ok());
        assert!(check_rpm(10_001).is_err());
    }
}
