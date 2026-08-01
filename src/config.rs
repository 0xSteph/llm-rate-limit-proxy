//! On-disk configuration store: the persisted source of truth (users, providers,
//! settings). Atomic writes, mode 0600, version-guarded loads. No HTTP lives here.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Bump when the on-disk schema changes incompatibly. A store written by a newer
/// build than the running one is refused rather than silently downgraded.
pub const STORE_VERSION: u32 = 1;

fn default_version() -> u32 {
    STORE_VERSION
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct StoredConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub users: Vec<User>,
    #[serde(default)]
    pub providers: Vec<Provider>,
    #[serde(default)]
    pub clients: Vec<ClientKey>,
    #[serde(default)]
    pub aliases: Vec<Alias>,
    #[serde(default)]
    pub settings: Settings,
}

/// A virtual model: a name a client can request that resolves to an ordered list
/// of concrete targets, tried in turn (fallback chain).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Alias {
    pub name: String,
    pub targets: Vec<AliasTarget>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AliasTarget {
    pub provider: String,
    pub model: String,
}

/// A minted client API key. The secret is shown to the user exactly once; only its
/// SHA-256 digest (+ last-4 for display) is ever stored.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClientKey {
    pub label: String,
    pub digest: String,
    pub last4: String,
    #[serde(default)]
    pub owner: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct User {
    pub username: String,
    pub pw_hash: String,
    pub role: Role,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Superuser,
    Admin,
    User,
}

impl Role {
    pub fn is_admin(self) -> bool {
        matches!(self, Role::Superuser | Role::Admin)
    }
}

/// An upstream LLM provider (base URL + a pool of API keys). Phase 1 gives this
/// behavior; Phase 0 only needs it to round-trip through the store.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Provider {
    pub name: String,
    pub base_url: String,
    #[serde(default)]
    pub keys: Vec<ProviderKey>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProviderKey {
    pub key: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_rpm")]
    pub rpm: usize,
    #[serde(default)]
    pub owner: String,
}

fn default_true() -> bool {
    true
}

fn default_rpm() -> usize {
    40
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Settings {
    #[serde(default = "default_history_days")]
    pub history_days: u32,
    #[serde(default = "default_max_inflight")]
    pub max_inflight: usize,
    #[serde(default = "default_models_ttl_secs")]
    pub models_ttl_secs: u64,
    /// Source addresses permitted to reach this proxy — bare IPs or CIDR blocks.
    /// Empty means everyone, which is the default: a proxy that refused all
    /// traffic the moment someone saved an empty field would be a bad surprise.
    /// Loopback is always allowed regardless.
    #[serde(default)]
    pub allow_from: Vec<String>,
    /// What each model would cost per million tokens at a paid provider, used to
    /// price the savings view. An assumption rather than a measurement — free
    /// tiers cost nothing, so the interesting figure is the counterfactual — and
    /// therefore editable, with the rate shown beside every row it produced.
    #[serde(default = "default_model_rates")]
    pub model_rates: std::collections::HashMap<String, crate::ledger::Rate>,
}

/// Opening assumptions for the savings view, in USD per million tokens.
///
/// Rounded from published list prices for the same models on paid providers at
/// the time of writing. They drift, which is why they are configurable; the
/// console shows which rate produced each row so a stale number is visible
/// rather than silently wrong.
fn default_model_rates() -> std::collections::HashMap<String, crate::ledger::Rate> {
    use crate::ledger::Rate;
    [
        (
            "z-ai/glm-5.2",
            Rate {
                input_per_mtok: 0.60,
                output_per_mtok: 2.00,
            },
        ),
        (
            "deepseek-ai/deepseek-v4-pro",
            Rate {
                input_per_mtok: 0.28,
                output_per_mtok: 1.10,
            },
        ),
        (
            "deepseek-ai/deepseek-v4-flash",
            Rate {
                input_per_mtok: 0.07,
                output_per_mtok: 0.30,
            },
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

fn default_history_days() -> u32 {
    30
}

/// Concurrent requests admitted before the proxy sheds. High enough that normal
/// agent fleets never see it; low enough that a runaway client can't exhaust
/// sockets and memory before anything else notices.
fn default_max_inflight() -> usize {
    512
}

/// How long a provider's model catalog is trusted. Catalogs change on the order
/// of weeks, so this is about bounding staleness, not tracking churn.
fn default_models_ttl_secs() -> u64 {
    600
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            history_days: default_history_days(),
            max_inflight: default_max_inflight(),
            models_ttl_secs: default_models_ttl_secs(),
            allow_from: Vec::new(),
            model_rates: default_model_rates(),
        }
    }
}

impl StoredConfig {
    /// The single superuser, if setup has run.
    pub fn superuser(&self) -> Option<&User> {
        self.users.iter().find(|u| u.role == Role::Superuser)
    }
}

/// Normalize a provider base URL for path-forwarding.
///
/// A request arrives with its full path (`/v1/chat/completions`) and that path is
/// forwarded verbatim, so the base must not itself end in `/v1` — the result is
/// `/v1/v1/chat/completions`, which no provider routes. Every OpenAI-compatible
/// client trains its users to write the base *with* `/v1`, so this is the
/// mistake people actually make, and what comes back is a bare router 404
/// ("404 page not found") that names nothing and points at nothing.
pub fn normalize_base_url(raw: &str) -> String {
    // Applied until it stops changing. Each rule can expose input for another —
    // a trailing slash hides whitespace from the trim, and stripping "/v1" can
    // reveal a slash underneath — so a single pass leaves results that are not
    // normal, and storing one bakes stray whitespace into every request URL
    // built from it.
    let mut out = raw;
    loop {
        let next = out.trim().trim_end_matches('/').trim();
        let next = next.strip_suffix("/v1").unwrap_or(next);
        if next == out {
            return out.to_string();
        }
        out = next;
    }
}

pub fn store_path(dir: &Path) -> PathBuf {
    dir.join("config.json")
}

/// Load the store. `Ok(None)` = fresh install (no store yet). `Err` = corrupt or
/// written by a newer build — a hard boot error, never a silent reset.
pub fn load(dir: &Path) -> Result<Option<StoredConfig>, String> {
    let path = store_path(dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    };
    let sc: StoredConfig = serde_json::from_slice(&bytes)
        .map_err(|e| format!("config store at {} is corrupt: {e}", path.display()))?;
    if sc.version > STORE_VERSION {
        return Err(format!(
            "config store version {} is newer than this build supports ({STORE_VERSION})",
            sc.version
        ));
    }
    Ok(Some(sc))
}

/// Persist the store atomically (write temp → chmod 0600 → rename over target) so a
/// crash mid-write can never leave a half-written or world-readable credential file.
pub fn save(dir: &Path, sc: &StoredConfig) -> Result<(), String> {
    let path = store_path(dir);
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(sc).map_err(|e| format!("serializing config: {e}"))?;
    std::fs::write(&tmp, &json).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| format!("renaming into {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StoredConfig {
        StoredConfig {
            version: STORE_VERSION,
            users: vec![User {
                username: "admin".into(),
                pw_hash: "pbkdf2$sha256$600000$salt$hash".into(),
                role: Role::Superuser,
            }],
            providers: vec![Provider {
                name: "nim".into(),
                base_url: "https://example.test".into(),
                keys: vec![ProviderKey {
                    key: "k".into(),
                    enabled: true,
                    rpm: 40,
                    owner: "admin".into(),
                }],
            }],
            clients: vec![],
            aliases: vec![],
            settings: Settings::default(),
        }
    }

    #[test]
    fn roundtrip_survives_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let sc = sample();
        save(dir.path(), &sc).unwrap();
        assert_eq!(load(dir.path()).unwrap().unwrap(), sc);
    }

    #[test]
    fn load_absent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).unwrap().is_none());
    }

    #[test]
    fn refuses_future_version() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(store_path(dir.path()), br#"{"version":999}"#).unwrap();
        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn refuses_corrupt_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(store_path(dir.path()), b"{ not json").unwrap();
        assert!(load(dir.path()).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn save_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), &sample()).unwrap();
        let mode = std::fs::metadata(store_path(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn superuser_found() {
        assert_eq!(sample().superuser().unwrap().username, "admin");
    }
}

#[cfg(test)]
mod base_url_tests {
    use super::*;

    // A base URL is typed by a person and a config store can be hand-edited or
    // corrupted, so both are untrusted input to code that runs at boot.
    proptest::proptest! {
        #[test]
        fn normalizing_never_panics_and_is_idempotent(raw in ".*") {
            let once = normalize_base_url(&raw);
            proptest::prop_assert_eq!(normalize_base_url(&once), once.clone());
            proptest::prop_assert!(!once.ends_with('/'), "left a trailing slash: {}", once);
            proptest::prop_assert!(!once.ends_with("/v1"), "left a /v1 suffix: {}", once);
        }

        /// However many the caller typed, the result carries none.
        #[test]
        fn any_number_of_v1_suffixes_leaves_at_most_one_removed(
            host in "https?://[a-z]{1,12}", slashes in 0usize..4
        ) {
            let raw = format!("{host}/v1{}", "/".repeat(slashes));
            proptest::prop_assert_eq!(normalize_base_url(&raw), host);
        }

        #[test]
        fn a_corrupt_store_is_refused_rather_than_trusted(raw in ".*") {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(store_path(dir.path()), raw.as_bytes()).unwrap();
            // Either it parses as a real store or it is an error. What it must
            // never do is panic at boot or silently reset somebody's config.
            let _ = load(dir.path());
        }
    }

    /// Requests are forwarded with their full path (`/v1/chat/completions`), so a
    /// base that already ends in `/v1` produces `/v1/v1/chat/completions`. Every
    /// OpenAI-compatible client trains its users to write the base *with* `/v1`,
    /// and the provider answers a bare router 404 that names nothing useful.
    #[test]
    fn a_v1_suffix_is_stripped_because_the_client_path_supplies_it() {
        assert_eq!(
            normalize_base_url("https://integrate.api.nvidia.com/v1"),
            "https://integrate.api.nvidia.com"
        );
        assert_eq!(
            normalize_base_url("https://integrate.api.nvidia.com/v1/"),
            "https://integrate.api.nvidia.com"
        );
    }

    #[test]
    fn trailing_slashes_and_whitespace_are_trimmed() {
        assert_eq!(normalize_base_url("  https://host/  "), "https://host");
    }

    /// A provider mounted under a prefix still works: the prefix is kept and only
    /// the version segment the client path supplies is removed.
    #[test]
    fn a_path_prefix_before_v1_is_preserved() {
        assert_eq!(
            normalize_base_url("https://host/api/v1"),
            "https://host/api"
        );
    }

    #[test]
    fn a_base_without_v1_is_left_alone() {
        assert_eq!(normalize_base_url("https://host"), "https://host");
        assert_eq!(
            normalize_base_url("https://host/v1beta"),
            "https://host/v1beta"
        );
    }
}
