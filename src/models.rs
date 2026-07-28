//! The model catalog: one merged `/v1/models` answer across every provider,
//! served from cache so a harness polling its catalog costs no rate budget.
//!
//! Two things make this more than a passthrough. Sluice fronts several
//! providers, so a forwarded request would return whichever provider happened
//! to win the lane and hide the rest; the catalogs are merged instead. And
//! aliases are real routable names that exist only here, so they belong in the
//! catalog — otherwise a harness listing models never discovers them.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::config::Alias;

/// A provider's catalog as last seen, with when it was fetched.
struct Entry {
    fetched: Instant,
    models: Vec<Value>,
}

pub struct Catalog {
    ttl: Duration,
    entries: Mutex<HashMap<String, Entry>>,
}

impl Catalog {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The provider's catalog if it is still fresh.
    pub fn fresh(&self, provider: &str, now: Instant) -> Option<Vec<Value>> {
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(provider)?;
        (now.duration_since(entry.fetched) < self.ttl).then(|| entry.models.clone())
    }

    /// The provider's catalog at any age.
    ///
    /// A model catalog is near-static, so a stale answer is overwhelmingly
    /// likely to be correct and is certainly more useful than an error. Losing
    /// the catalog is enough to make a harness look broken at startup, so an
    /// upstream blip should not be able to cause that.
    pub fn stale(&self, provider: &str) -> Option<Vec<Value>> {
        Some(self.entries.lock().unwrap().get(provider)?.models.clone())
    }

    pub fn put(&self, provider: &str, models: Vec<Value>, now: Instant) {
        self.entries.lock().unwrap().insert(
            provider.to_string(),
            Entry {
                fetched: now,
                models,
            },
        );
    }
}

/// Pull the `data` array out of an OpenAI-shaped catalog response.
pub fn extract(body: &Value) -> Vec<Value> {
    body.get("data")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Merge provider catalogs and alias names into one OpenAI-shaped response.
///
/// Ids are deduped: the same model offered by two providers is one entry, since
/// a client picks a name and Sluice decides where it runs. First occurrence
/// wins, so provider order in config decides which metadata is shown.
pub fn merge(catalogs: &[Vec<Value>], aliases: &[Alias]) -> Value {
    let mut seen: Vec<String> = Vec::new();
    let mut data: Vec<Value> = Vec::new();

    for name in aliases.iter().map(|a| &a.name) {
        if !seen.iter().any(|s| s == name) {
            seen.push(name.clone());
            data.push(json!({
                "id": name,
                "object": "model",
                "owned_by": "sluice",
            }));
        }
    }

    for entry in catalogs.iter().flatten() {
        let Some(id) = entry.get("id").and_then(|i| i.as_str()) else {
            continue;
        };
        if seen.iter().any(|s| s == id) {
            continue;
        }
        seen.push(id.to_string());
        data.push(entry.clone());
    }

    json!({ "object": "list", "data": data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Alias, AliasTarget};

    fn model(id: &str) -> Value {
        json!({"id": id, "object": "model", "owned_by": "someone"})
    }

    fn alias(name: &str) -> Alias {
        Alias {
            name: name.into(),
            targets: vec![AliasTarget {
                provider: "nim".into(),
                model: "real".into(),
            }],
        }
    }

    fn ids(v: &Value) -> Vec<String> {
        v["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["id"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn merges_every_providers_catalog() {
        let merged = merge(&[vec![model("a")], vec![model("b")]], &[]);
        assert_eq!(ids(&merged), vec!["a", "b"]);
        assert_eq!(merged["object"], "list");
    }

    #[test]
    fn a_model_offered_by_two_providers_appears_once() {
        let merged = merge(&[vec![model("same")], vec![model("same")]], &[]);
        assert_eq!(ids(&merged), vec!["same"]);
    }

    /// Aliases are routable names that exist only in Sluice. A harness that
    /// lists models and never sees them cannot offer them to the user at all.
    #[test]
    fn aliases_are_listed_as_models() {
        let merged = merge(&[vec![model("real")]], &[alias("virtual")]);
        assert_eq!(ids(&merged), vec!["virtual", "real"]);
    }

    #[test]
    fn an_alias_shadowing_a_real_model_is_not_duplicated() {
        let merged = merge(&[vec![model("shared")]], &[alias("shared")]);
        assert_eq!(ids(&merged), vec!["shared"]);
        assert_eq!(
            merged["data"][0]["owned_by"], "sluice",
            "the alias is what routing will actually use, so it must be what is shown"
        );
    }

    #[test]
    fn entries_without_an_id_are_skipped() {
        let merged = merge(&[vec![json!({"object": "model"}), model("ok")]], &[]);
        assert_eq!(ids(&merged), vec!["ok"]);
    }

    #[test]
    fn extract_reads_the_data_array_and_tolerates_junk() {
        assert_eq!(extract(&json!({"data": [model("x")]})).len(), 1);
        assert!(extract(&json!({"unexpected": true})).is_empty());
    }

    #[test]
    fn a_cached_catalog_is_served_until_it_expires() {
        let cat = Catalog::new(Duration::from_secs(60));
        let start = Instant::now();
        cat.put("nim", vec![model("a")], start);
        assert!(cat.fresh("nim", start + Duration::from_secs(59)).is_some());
        assert!(cat.fresh("nim", start + Duration::from_secs(61)).is_none());
    }

    #[test]
    fn an_unknown_provider_has_nothing_cached() {
        let cat = Catalog::new(Duration::from_secs(60));
        assert!(cat.fresh("nope", Instant::now()).is_none());
        assert!(cat.stale("nope").is_none());
    }

    /// Catalogs are near-static, so an expired copy beats failing the request —
    /// losing the catalog makes a harness look broken at startup.
    #[test]
    fn an_expired_catalog_is_still_available_as_a_fallback() {
        let cat = Catalog::new(Duration::from_secs(60));
        let start = Instant::now();
        cat.put("nim", vec![model("a")], start);
        let long_after = start + Duration::from_secs(3600);
        assert!(cat.fresh("nim", long_after).is_none());
        assert_eq!(cat.stale("nim").unwrap().len(), 1);
    }
}
