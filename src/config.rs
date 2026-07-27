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
}

fn default_history_days() -> u32 {
    30
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            history_days: default_history_days(),
        }
    }
}

impl StoredConfig {
    /// The single superuser, if setup has run.
    pub fn superuser(&self) -> Option<&User> {
        self.users.iter().find(|u| u.role == Role::Superuser)
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
