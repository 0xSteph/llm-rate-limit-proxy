//! Lifetime token usage and what it would have cost elsewhere.
//!
//! Metrics live in memory and start from zero every restart, which is right for
//! "how is it behaving now" and useless for "what has this saved me". This keeps
//! a per-model running total on disk instead, so the figure is a property of the
//! installation rather than of the current process.
//!
//! The saving is counterfactual by nature: these tokens were served on free
//! tiers, so the real spend is zero and the interesting number is what the same
//! traffic would have cost at a paid provider's rates. That makes the rate table
//! an assumption, not a measurement, so it is configurable and the console shows
//! which rates produced the figure. A number this satisfying to look at should be
//! auditable.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// Cumulative usage for one model.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq)]
pub struct Usage {
    pub requests: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

impl Usage {
    fn plus(self, o: Usage) -> Usage {
        Usage {
            requests: self.requests + o.requests,
            prompt_tokens: self.prompt_tokens + o.prompt_tokens,
            completion_tokens: self.completion_tokens + o.completion_tokens,
        }
    }
}

/// Dollars per million tokens, in and out.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct Rate {
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
}

/// Fallback for a model with no configured rate. Deliberately modest: a saving
/// that overstates itself is worse than one that undercounts, because the whole
/// point of the number is to be believed.
pub const DEFAULT_RATE: Rate = Rate {
    input_per_mtok: 0.50,
    output_per_mtok: 1.50,
};

#[derive(Serialize, Debug, PartialEq)]
pub struct Saving {
    pub model: String,
    pub requests: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    /// The rate this row was priced at, so the figure can be checked.
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
    pub usd: f64,
}

pub struct Ledger {
    path: Option<PathBuf>,
    /// Totals as of process start. Metrics restart at zero, so every published
    /// figure is this plus whatever the current process has since served —
    /// without it, a restart would appear to erase the history.
    baseline: RwLock<HashMap<String, Usage>>,
    /// Baseline plus the current process, refreshed on each snapshot tick.
    live: RwLock<HashMap<String, Usage>>,
}

impl Ledger {
    pub fn load(path: Option<PathBuf>) -> Self {
        let stored: HashMap<String, Usage> = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Ledger {
            path,
            baseline: RwLock::new(stored.clone()),
            live: RwLock::new(stored),
        }
    }

    /// Fold this process's per-model counters onto the baseline and persist.
    ///
    /// Takes the current absolute values rather than a delta, because that is
    /// what the metrics registry can report and it makes the operation
    /// idempotent — running it twice on the same tick cannot double-count.
    pub fn absorb(&self, current: &[(String, Usage)]) {
        let baseline = self.baseline.read().unwrap();
        let mut live = self.live.write().unwrap();
        for (model, now) in current {
            let base = baseline.get(model).copied().unwrap_or_default();
            live.insert(model.clone(), base.plus(*now));
        }
        if let Some(p) = &self.path {
            if let Ok(s) = serde_json::to_string(&*live) {
                let _ = std::fs::write(p, s);
            }
        }
    }

    /// Lifetime usage priced at `rates`, largest saving first.
    pub fn savings(&self, rates: &HashMap<String, Rate>) -> Vec<Saving> {
        let live = self.live.read().unwrap();
        let mut out: Vec<Saving> = live
            .iter()
            .filter(|(_, u)| u.prompt_tokens > 0 || u.completion_tokens > 0)
            .map(|(model, u)| {
                let rate = rates.get(model).copied().unwrap_or(DEFAULT_RATE);
                let usd = (u.prompt_tokens as f64 / 1_000_000.0) * rate.input_per_mtok
                    + (u.completion_tokens as f64 / 1_000_000.0) * rate.output_per_mtok;
                Saving {
                    model: model.clone(),
                    requests: u.requests,
                    prompt_tokens: u.prompt_tokens,
                    completion_tokens: u.completion_tokens,
                    input_per_mtok: rate.input_per_mtok,
                    output_per_mtok: rate.output_per_mtok,
                    usd,
                }
            })
            .collect();
        out.sort_by(|a, b| b.usd.total_cmp(&a.usd));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(r: u64, p: u64, c: u64) -> Usage {
        Usage {
            requests: r,
            prompt_tokens: p,
            completion_tokens: c,
        }
    }

    #[test]
    fn a_restart_does_not_erase_what_came_before() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage.json");

        let first = Ledger::load(Some(path.clone()));
        first.absorb(&[("m".into(), usage(10, 1_000, 100))]);

        // A new process: metrics are back at zero and climb again from there.
        let second = Ledger::load(Some(path.clone()));
        second.absorb(&[("m".into(), usage(3, 400, 40))]);

        let s = &second.savings(&HashMap::new())[0];
        assert_eq!(s.requests, 13, "totals must span processes");
        assert_eq!(s.prompt_tokens, 1_400);
        assert_eq!(s.completion_tokens, 140);
    }

    #[test]
    fn absorbing_the_same_counters_twice_does_not_double_count() {
        // The tick reports absolute values, so a retry or an overlapping tick
        // must be harmless — otherwise the headline number inflates on its own.
        let led = Ledger::load(None);
        led.absorb(&[("m".into(), usage(5, 500, 50))]);
        led.absorb(&[("m".into(), usage(5, 500, 50))]);
        assert_eq!(led.savings(&HashMap::new())[0].prompt_tokens, 500);
    }

    #[test]
    fn cost_is_priced_per_million_tokens_each_way() {
        let led = Ledger::load(None);
        led.absorb(&[("m".into(), usage(1, 2_000_000, 500_000))]);
        let rates = HashMap::from([(
            "m".to_string(),
            Rate {
                input_per_mtok: 0.60,
                output_per_mtok: 2.00,
            },
        )]);
        // 2 Mtok in at $0.60 = $1.20, 0.5 Mtok out at $2.00 = $1.00.
        assert!((led.savings(&rates)[0].usd - 2.20).abs() < 1e-9);
    }

    #[test]
    fn an_unpriced_model_falls_back_rather_than_vanishing() {
        let led = Ledger::load(None);
        led.absorb(&[("surprise".into(), usage(1, 1_000_000, 0))]);
        let s = &led.savings(&HashMap::new())[0];
        assert_eq!(s.input_per_mtok, DEFAULT_RATE.input_per_mtok);
        assert!((s.usd - DEFAULT_RATE.input_per_mtok).abs() < 1e-9);
    }

    #[test]
    fn models_that_served_nothing_are_omitted() {
        // /v1/props and /v1/models are recorded as models by the metrics layer
        // but carry no tokens; a row of zeroes priced at zero is noise.
        let led = Ledger::load(None);
        led.absorb(&[
            ("real".into(), usage(1, 100, 10)),
            ("props".into(), usage(9, 0, 0)),
        ]);
        let s = led.savings(&HashMap::new());
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].model, "real");
    }

    #[test]
    fn the_biggest_saving_is_listed_first() {
        let led = Ledger::load(None);
        led.absorb(&[
            ("small".into(), usage(1, 1_000, 0)),
            ("large".into(), usage(1, 9_000_000, 0)),
        ]);
        let s = led.savings(&HashMap::new());
        assert_eq!(s[0].model, "large");
    }
}
