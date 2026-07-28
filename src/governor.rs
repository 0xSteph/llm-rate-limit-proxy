//! Model-pressure governor: a per-model concurrency gate beside the rate limiter.
//!
//! Providers cap how many requests may be *in flight* on a model at once, which
//! is a different resource from the per-key request rate and is shared across
//! every key. Failing over to another key cannot relieve it, so the usual
//! response to a rebuff — bench the lane, try the next one — burns healthy key
//! capacity on an attempt that was never going to work.
//!
//! Detection is behavioral rather than a string match on the provider's error.
//! Per-key rate limiters are independent, and the pool already paces each key
//! under its own budget, so rebuffs on one key say nothing about another. When
//! the *same model* is rebuffed on two different keys within seconds, that
//! correlation is the evidence: the constraint is model-scoped. This needs no
//! knowledge of the provider's error wording, so it keeps working when that
//! wording changes and works across providers that phrase it differently.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Rebuffs older than this are no longer evidence of anything current.
const EVIDENCE_WINDOW: Duration = Duration::from_secs(10);

/// Distinct keys that must be rebuffed on one model before we hold the model
/// responsible. Two suffices: independent limiters do not correlate by chance.
const KEYS_TO_INDICT: usize = 2;

/// A governed model with no rebuff for this long returns to ungoverned. The
/// provider's worker pool is shared infrastructure, so the real ceiling moves
/// with other tenants' load and a cap we picked minutes ago is stale.
const DISSOLVE_AFTER: Duration = Duration::from_secs(10 * 60);

#[derive(Default)]
struct ModelState {
    /// Concurrency cap; 0 means ungoverned.
    limit: usize,
    /// Permits currently held — requests in flight upstream on this model.
    inflight: usize,
    /// Recent rebuffs as (when, which lane), pruned to `EVIDENCE_WINDOW`.
    rebuffs: Vec<(Instant, usize)>,
    last_rebuff: Option<Instant>,
}

impl ModelState {
    fn prune(&mut self, now: Instant) {
        self.rebuffs
            .retain(|(at, _)| now.duration_since(*at) < EVIDENCE_WINDOW);
    }

    /// How many distinct keys have been rebuffed inside the evidence window.
    fn implicated_keys(&self) -> usize {
        let mut lanes: Vec<usize> = self.rebuffs.iter().map(|(_, lane)| *lane).collect();
        lanes.sort_unstable();
        lanes.dedup();
        lanes.len()
    }
}

/// A model under a concurrency cap, as reported to operators.
#[derive(serde::Serialize, Debug, PartialEq)]
pub struct ModelPressure {
    pub model: String,
    pub limit: usize,
    pub inflight: usize,
}

#[derive(Default)]
pub struct Governor {
    models: Mutex<HashMap<String, ModelState>>,
}

impl Governor {
    /// Record that `model` was rebuffed while being served by `lane`.
    ///
    /// Once two distinct keys are implicated the model is governed, starting at
    /// half the concurrency we were actually running. Halving is deliberate: the
    /// true ceiling is unknown and shared with other tenants, so the useful move
    /// is to back off decisively and climb back, not to guess a number.
    pub fn note_rebuff(&self, model: &str, lane: usize, now: Instant) {
        let mut models = self.models.lock().unwrap();
        let state = models.entry(model.to_string()).or_default();
        state.prune(now);
        state.rebuffs.push((now, lane));
        state.last_rebuff = Some(now);

        if state.implicated_keys() >= KEYS_TO_INDICT {
            let observed = state.inflight.max(1);
            let backed_off = (observed / 2).max(1);
            let was = state.limit;
            state.limit = if state.limit == 0 {
                backed_off
            } else {
                state.limit.min(backed_off)
            };
            if state.limit != was {
                // The one moment worth announcing: from here requests wait on a
                // gate that consumes no rate budget, so every rate figure will
                // read low while the proxy is in fact working as hard as allowed.
                println!(
                    "  governing {model} at {} concurrent ({} keys rebuffed, {} in flight)",
                    state.limit,
                    state.implicated_keys(),
                    observed
                );
            }
        }
    }

    /// Current concurrency cap for `model`; 0 means ungoverned. A model that has
    /// been quiet for `DISSOLVE_AFTER` releases its cap here.
    pub fn limit(&self, model: &str, now: Instant) -> usize {
        let mut models = self.models.lock().unwrap();
        let Some(state) = models.get_mut(model) else {
            return 0;
        };
        if state
            .last_rebuff
            .is_some_and(|at| now.duration_since(at) >= DISSOLVE_AFTER)
        {
            state.limit = 0;
            state.rebuffs.clear();
            state.last_rebuff = None;
        }
        state.limit
    }

    /// Every model currently under a cap, with its cap and live concurrency.
    ///
    /// This is the operator-facing answer to "why is it slow when the keys look
    /// idle". A request gated here never reaches the rate limiter, so rate-based
    /// capacity reads 0% while everything stalls; without this the blocking
    /// constraint is invisible.
    pub fn pressured(&self, now: Instant) -> Vec<ModelPressure> {
        let mut models = self.models.lock().unwrap();
        let mut out: Vec<ModelPressure> = models
            .iter_mut()
            .filter_map(|(model, state)| {
                if state
                    .last_rebuff
                    .is_some_and(|at| now.duration_since(at) >= DISSOLVE_AFTER)
                {
                    state.limit = 0;
                    state.rebuffs.clear();
                    state.last_rebuff = None;
                }
                (state.limit > 0).then(|| ModelPressure {
                    model: model.clone(),
                    limit: state.limit,
                    inflight: state.inflight,
                })
            })
            .collect();
        out.sort_by(|a, b| a.model.cmp(&b.model));
        out
    }

    /// Requests in flight on `model` right now.
    pub fn inflight(&self, model: &str) -> usize {
        self.models
            .lock()
            .unwrap()
            .get(model)
            .map_or(0, |s| s.inflight)
    }
}

/// Claim a concurrency slot on `model`, or `None` when it is at its cap.
/// Ungoverned models always admit. The permit releases on drop.
pub fn admit(gov: &Arc<Governor>, model: &str, now: Instant) -> Option<ModelPermit> {
    let limit = gov.limit(model, now);
    let mut models = gov.models.lock().unwrap();
    let state = models.entry(model.to_string()).or_default();
    if limit > 0 && state.inflight >= limit {
        return None;
    }
    state.inflight += 1;
    Some(ModelPermit {
        governor: gov.clone(),
        model: model.to_string(),
    })
}

/// Holds one model-concurrency slot, releasing it on drop so a request frees it
/// however it ends.
pub struct ModelPermit {
    governor: Arc<Governor>,
    model: String,
}

impl Drop for ModelPermit {
    fn drop(&mut self) {
        if let Some(state) = self.governor.models.lock().unwrap().get_mut(&self.model) {
            state.inflight = state.inflight.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn governor() -> Arc<Governor> {
        Arc::new(Governor::default())
    }

    #[test]
    fn a_model_starts_ungoverned() {
        let g = governor();
        assert_eq!(g.limit("m", Instant::now()), 0);
    }

    /// The discriminator that makes string matching unnecessary: one key being
    /// rebuffed over and over is a lane problem, and benching that lane is the
    /// right answer. Governing the model here would throttle every healthy key
    /// because one key is sick.
    #[test]
    fn repeated_rebuffs_on_one_key_do_not_indict_the_model() {
        let g = governor();
        let now = Instant::now();
        for _ in 0..10 {
            g.note_rebuff("m", 0, now);
        }
        assert_eq!(g.limit("m", now), 0);
    }

    /// Independent per-key limiters do not fail together by chance, so the same
    /// model being rebuffed on two different keys within seconds is evidence the
    /// constraint is the model — no knowledge of the error wording required.
    #[test]
    fn rebuffs_across_distinct_keys_indict_the_model() {
        let g = governor();
        let now = Instant::now();
        g.note_rebuff("m", 0, now);
        assert_eq!(g.limit("m", now), 0, "one key is not yet evidence");
        g.note_rebuff("m", 1, now);
        assert!(g.limit("m", now) > 0, "two distinct keys indicts the model");
    }

    #[test]
    fn evidence_older_than_the_window_is_not_counted() {
        let g = governor();
        let start = Instant::now();
        g.note_rebuff("m", 0, start);
        // The first rebuff has aged out by the time the second key fails, so the
        // two never coexist as evidence and the model stays ungoverned.
        let later = start + EVIDENCE_WINDOW + Duration::from_secs(1);
        g.note_rebuff("m", 1, later);
        assert_eq!(g.limit("m", later), 0);
    }

    #[test]
    fn one_models_pressure_does_not_govern_another() {
        let g = governor();
        let now = Instant::now();
        g.note_rebuff("busy", 0, now);
        g.note_rebuff("busy", 1, now);
        assert!(g.limit("busy", now) > 0);
        assert_eq!(g.limit("quiet", now), 0, "pressure is per model");
    }

    #[test]
    fn a_governed_model_admits_up_to_its_cap_then_refuses() {
        let g = governor();
        let now = Instant::now();
        // Four in flight when the pressure shows up, so the cap lands at two.
        let held: Vec<_> = (0..4).map(|_| admit(&g, "m", now).unwrap()).collect();
        g.note_rebuff("m", 0, now);
        g.note_rebuff("m", 1, now);
        assert_eq!(g.limit("m", now), 2);
        drop(held);

        let _a = admit(&g, "m", now).expect("first fits under the cap");
        let _b = admit(&g, "m", now).expect("second fits under the cap");
        assert!(admit(&g, "m", now).is_none(), "third exceeds the cap");
    }

    #[test]
    fn a_permit_frees_its_slot_on_drop() {
        let g = governor();
        let now = Instant::now();
        let held: Vec<_> = (0..2).map(|_| admit(&g, "m", now).unwrap()).collect();
        g.note_rebuff("m", 0, now);
        g.note_rebuff("m", 1, now);
        drop(held);
        assert_eq!(g.inflight("m"), 0);
        assert!(admit(&g, "m", now).is_some(), "freed slots are reusable");
    }

    #[test]
    fn an_ungoverned_model_admits_without_limit() {
        let g = governor();
        let now = Instant::now();
        let held: Vec<_> = (0..64).map(|_| admit(&g, "m", now)).collect();
        assert!(held.iter().all(|p| p.is_some()));
    }

    #[test]
    fn pressured_reports_only_governed_models() {
        let g = governor();
        let now = Instant::now();
        let _quiet = admit(&g, "quiet", now).unwrap();
        assert!(g.pressured(now).is_empty(), "nothing is under pressure yet");

        g.note_rebuff("busy", 0, now);
        g.note_rebuff("busy", 1, now);
        let reported = g.pressured(now);
        assert_eq!(reported.len(), 1, "only the governed model is reported");
        assert_eq!(reported[0].model, "busy");
        assert!(reported[0].limit > 0);
    }

    #[test]
    fn a_quiet_model_returns_to_ungoverned() {
        let g = governor();
        let start = Instant::now();
        g.note_rebuff("m", 0, start);
        g.note_rebuff("m", 1, start);
        assert!(g.limit("m", start) > 0);
        let much_later = start + DISSOLVE_AFTER + Duration::from_secs(1);
        assert_eq!(
            g.limit("m", much_later),
            0,
            "the provider's ceiling moves with other tenants; a stale cap is wrong"
        );
    }
}
