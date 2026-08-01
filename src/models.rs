//! The model catalog: one merged `/v1/models` answer across every provider,
//! served from cache so a harness polling its catalog costs no rate budget.
//!
//! Two things make this more than a passthrough. Sluice fronts several
//! providers, so a forwarded request would return whichever provider happened
//! to win the lane and hide the rest; the catalogs are merged instead. And
//! aliases are real routable names that exist only here, so they belong in the
//! catalog — otherwise a harness listing models never discovers them.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::config::Alias;

/// A provider's catalog as last seen, with when it was fetched.
struct Entry {
    fetched: Instant,
    models: Vec<Value>,
}

/// Context ceilings, learned from providers rather than configured.
///
/// The OpenAI catalog format has no field for a context window, so every client
/// downstream of us is guessing at one — and a guess that is too high does not
/// fail at startup, it fails deep into a long session. Providers state the real
/// figure only when refusing a request that exceeded it, so that refusal is the
/// one moment the number is knowable. Recording it there lets the catalog answer
/// the question from then on.
#[derive(Default)]
pub struct Limits(Mutex<HashMap<String, u64>>);

impl Limits {
    /// Record a ceiling observed for `model`, keeping the smallest seen.
    ///
    /// Smallest rather than latest because keys can land on differently
    /// configured deployments of the same model; publishing the roomier one
    /// would hand clients a number that fails against the tighter one.
    pub fn learn(&self, model: &str, tokens: u64) {
        let mut m = self.0.lock().unwrap();
        let slot = m.entry(model.to_string()).or_insert(tokens);
        *slot = (*slot).min(tokens);
    }

    pub fn known(&self, model: &str) -> Option<u64> {
        self.0.lock().unwrap().get(model).copied()
    }
}

pub struct Catalog {
    /// Atomic so a settings change takes effect on the next lookup rather than
    /// at the next restart — the console offers this as a live setting.
    ttl_secs: AtomicU64,
    entries: Mutex<HashMap<String, Entry>>,
}

impl Catalog {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl_secs: AtomicU64::new(ttl.as_secs()),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Change how long a catalog is trusted, effective on the next lookup.
    pub fn set_ttl_secs(&self, secs: u64) {
        self.ttl_secs.store(secs, Ordering::Relaxed);
    }

    /// The provider's catalog if it is still fresh.
    pub fn fresh(&self, provider: &str, now: Instant) -> Option<Vec<Value>> {
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(provider)?;
        let ttl = Duration::from_secs(self.ttl_secs.load(Ordering::Relaxed));
        (now.duration_since(entry.fetched) < ttl).then(|| entry.models.clone())
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

    /// Which providers list `model` in their catalog, sorted for a stable plan.
    ///
    /// Routing a model to a provider that doesn't serve it spends a rate slot to
    /// earn a 404, then fails over — so with more than one provider configured
    /// the catalog is the difference between one clean call and a tour of every
    /// key you own.
    pub fn providers_offering(&self, model: &str) -> Vec<String> {
        let entries = self.entries.lock().unwrap();
        let mut names: Vec<String> = entries
            .iter()
            .filter(|(_, entry)| {
                entry
                    .models
                    .iter()
                    .any(|m| m.get("id").and_then(|i| i.as_str()) == Some(model))
            })
            .map(|(name, _)| name.clone())
            .collect();
        names.sort();
        names
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
pub fn merge(catalogs: &[Vec<Value>], aliases: &[Alias], limits: &Limits) -> Value {
    let mut seen: Vec<String> = Vec::new();
    let mut data: Vec<Value> = Vec::new();

    // Publish a learned ceiling under both spellings in circulation: vLLM calls
    // it `max_model_len`, OpenRouter calls it `context_length`, and a harness
    // reads whichever one it was written against. Silence for models we have
    // never seen refuse a request — an absent field makes a client fall back to
    // its own default, while a wrong field makes it confidently overflow.
    let annotate = |mut entry: Value, id: &str| -> Value {
        if let (Some(n), Some(obj)) = (limits.known(id), entry.as_object_mut()) {
            obj.insert("context_length".into(), json!(n));
            obj.insert("max_model_len".into(), json!(n));
        }
        entry
    };

    for name in aliases.iter().map(|a| &a.name) {
        if !seen.iter().any(|s| s == name) {
            seen.push(name.clone());
            data.push(annotate(
                json!({
                    "id": name,
                    "object": "model",
                    "owned_by": "sluice",
                }),
                name,
            ));
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
        let id = id.to_string();
        data.push(annotate(entry.clone(), &id));
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
        let merged = merge(
            &[vec![model("a")], vec![model("b")]],
            &[],
            &Limits::default(),
        );
        assert_eq!(ids(&merged), vec!["a", "b"]);
        assert_eq!(merged["object"], "list");
    }

    #[test]
    fn a_learned_context_ceiling_is_published_to_clients() {
        let limits = Limits::default();
        limits.learn("glm", 202_752);

        let merged = merge(&[vec![model("glm"), model("other")]], &[], &limits);
        let glm = &merged["data"][0];

        // Two spellings because clients disagree: vLLM publishes `max_model_len`,
        // OpenRouter publishes `context_length`, and a harness reads whichever it
        // was written against. Both name the same learned number.
        assert_eq!(glm["context_length"], 202_752, "OpenRouter spelling");
        assert_eq!(glm["max_model_len"], 202_752, "vLLM spelling");

        // A model we have never overflowed must claim nothing rather than guess.
        assert!(merged["data"][1].get("context_length").is_none());
    }

    #[test]
    fn the_smallest_observed_ceiling_wins() {
        // Different keys can land on differently-configured deployments of the
        // same model. Publishing the larger one would hand clients a number that
        // fails on some requests, so keep the one that is safe everywhere.
        let limits = Limits::default();
        limits.learn("m", 202_752);
        limits.learn("m", 131_072);
        limits.learn("m", 202_752);
        assert_eq!(limits.known("m"), Some(131_072));
    }

    #[test]
    fn a_model_offered_by_two_providers_appears_once() {
        let merged = merge(
            &[vec![model("same")], vec![model("same")]],
            &[],
            &Limits::default(),
        );
        assert_eq!(ids(&merged), vec!["same"]);
    }

    /// Aliases are routable names that exist only in Sluice. A harness that
    /// lists models and never sees them cannot offer them to the user at all.
    #[test]
    fn aliases_are_listed_as_models() {
        let merged = merge(
            &[vec![model("real")]],
            &[alias("virtual")],
            &Limits::default(),
        );
        assert_eq!(ids(&merged), vec!["virtual", "real"]);
    }

    #[test]
    fn an_alias_shadowing_a_real_model_is_not_duplicated() {
        let merged = merge(
            &[vec![model("shared")]],
            &[alias("shared")],
            &Limits::default(),
        );
        assert_eq!(ids(&merged), vec!["shared"]);
        assert_eq!(
            merged["data"][0]["owned_by"], "sluice",
            "the alias is what routing will actually use, so it must be what is shown"
        );
    }

    #[test]
    fn entries_without_an_id_are_skipped() {
        let merged = merge(
            &[vec![json!({"object": "model"}), model("ok")]],
            &[],
            &Limits::default(),
        );
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
    fn providers_offering_names_only_those_that_list_the_model() {
        let cat = Catalog::new(Duration::from_secs(60));
        let now = Instant::now();
        cat.put("nim", vec![model("shared"), model("nim-only")], now);
        cat.put("together", vec![model("shared")], now);
        assert_eq!(cat.providers_offering("shared"), vec!["nim", "together"]);
        assert_eq!(cat.providers_offering("nim-only"), vec!["nim"]);
        assert!(cat.providers_offering("nowhere").is_empty());
    }

    /// Offered as a live setting, so it has to behave like one.
    #[test]
    fn shortening_the_ttl_expires_a_catalog_immediately() {
        let cat = Catalog::new(Duration::from_secs(600));
        let start = Instant::now();
        cat.put("nim", vec![model("a")], start);
        let later = start + Duration::from_secs(60);
        assert!(cat.fresh("nim", later).is_some(), "fresh under a 600s ttl");
        cat.set_ttl_secs(30);
        assert!(cat.fresh("nim", later).is_none(), "stale under a 30s ttl");
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
