//! Provider-aware key pool. One "lane" per enabled API key across all configured
//! providers, each governed by an exact sliding-window limiter: N requests per
//! rolling window, matching a real provider's limiter rather than a burstable
//! token bucket.

use std::collections::VecDeque;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::StoredConfig;

/// A provider's real per-key rate window; requests are limited per this span.
pub const PROVIDER_WINDOW: Duration = Duration::from_secs(60);

/// Slack added to the enforcement window so a boundary-timed request can't land
/// inside the provider's real window after forwarding latency or clock skew.
pub const JITTER_MARGIN: Duration = Duration::from_secs(1);

/// Exact "N requests per rolling `window`" limiter. Time is injected so behavior
/// is deterministically testable without real waiting.
pub struct SlidingWindow {
    limit: usize,
    window: Duration,
    hits: VecDeque<Instant>,
}

impl SlidingWindow {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            hits: VecDeque::new(),
        }
    }

    fn prune(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.window);
        while let Some(&front) = self.hits.front() {
            match cutoff {
                Some(c) if front <= c => {
                    self.hits.pop_front();
                }
                _ => break,
            }
        }
    }

    /// Hits still inside the window — how much of this key's budget is spent.
    pub fn load(&mut self, now: Instant) -> usize {
        self.prune(now);
        self.hits.len()
    }

    /// Grant a slot at `now`, or report when the next slot frees.
    /// `Ok(())` records a hit and grants; `Err(retry_at)` means saturated.
    pub fn try_acquire(&mut self, now: Instant) -> Result<(), Instant> {
        self.prune(now);
        if self.hits.len() < self.limit {
            self.hits.push_back(now);
            Ok(())
        } else {
            // The oldest hit leaves the window at oldest + window; a slot frees then.
            match self.hits.front() {
                Some(&oldest) => Err(oldest + self.window),
                None => Err(now + self.window), // limit == 0: never grants
            }
        }
    }
}

/// One upstream lane: an API key on a provider, with its own limiter.
pub struct Lane {
    pub provider: String,
    pub base_url: String,
    pub key: String,
    pub rpm: usize,
    limiter: Mutex<SlidingWindow>,
    cooldown_until: Mutex<Option<Instant>>,
}

impl Lane {
    fn new(spec: LaneSpec, window: Duration) -> Self {
        Self {
            limiter: Mutex::new(SlidingWindow::new(spec.rpm, window)),
            cooldown_until: Mutex::new(None),
            provider: spec.provider,
            base_url: spec.base_url,
            key: spec.key,
            rpm: spec.rpm,
        }
    }

    /// Take this lane out of rotation until `until`. A key that just answered 429
    /// or 5xx will answer the same way to the next request, so the rebuff has to
    /// be remembered by the pool rather than only by the request that found it.
    pub fn bench(&self, until: Instant) {
        let mut cooldown = self.cooldown_until.lock().unwrap();
        // Never shorten a bench already in force: concurrent failures on the same
        // lane must not let a smaller backoff cancel a larger one.
        *cooldown = Some(cooldown.map_or(until, |current| current.max(until)));
    }

    pub fn benched(&self, now: Instant) -> bool {
        self.cooldown_until
            .lock()
            .unwrap()
            .is_some_and(|until| until > now)
    }

    /// When this lane's cooldown ends, if it is benched right now.
    pub fn cooldown_ends(&self, now: Instant) -> Option<Instant> {
        self.cooldown_until
            .lock()
            .unwrap()
            .filter(|&until| until > now)
    }

    pub fn try_acquire(&self, now: Instant) -> Result<(), Instant> {
        self.limiter.lock().unwrap().try_acquire(now)
    }

    /// Spent budget in the current window, for picking the least-loaded lane.
    pub fn load(&self, now: Instant) -> usize {
        self.limiter.lock().unwrap().load(now)
    }

    /// Adopt another lane's spent budget and cooldown. Only the hits are copied,
    /// not the limit, so a key whose rpm was just lowered is held to the new
    /// figure immediately rather than from the next window.
    fn carry_from(&self, old: &Lane) {
        let hits = old.limiter.lock().unwrap().hits.clone();
        self.limiter.lock().unwrap().hits = hits;
        *self.cooldown_until.lock().unwrap() = *old.cooldown_until.lock().unwrap();
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LaneSpec {
    pub provider: String,
    pub base_url: String,
    pub key: String,
    pub rpm: usize,
}

/// Flatten every enabled, non-zero-rpm key across all providers into lane specs.
pub fn lane_specs(sc: &StoredConfig) -> Vec<LaneSpec> {
    let mut specs = Vec::new();
    for p in &sc.providers {
        for k in &p.keys {
            if k.enabled && k.rpm > 0 {
                specs.push(LaneSpec {
                    provider: p.name.clone(),
                    base_url: p.base_url.clone(),
                    key: k.key.clone(),
                    rpm: k.rpm,
                });
            }
        }
    }
    specs
}

pub struct Pool {
    lanes: Vec<Lane>,
    window: Duration,
}

impl Pool {
    pub fn new(specs: Vec<LaneSpec>) -> Self {
        Self::for_provider_window(specs, PROVIDER_WINDOW)
    }

    /// Build lanes that enforce over the provider window *plus* the jitter margin,
    /// keeping the proxy strictly under the provider's real per-key limit.
    pub fn for_provider_window(specs: Vec<LaneSpec>, provider_window: Duration) -> Self {
        Self::with_window(specs, provider_window + JITTER_MARGIN)
    }

    /// Build with an exact enforcement window (no margin) — tests use this to
    /// exercise pacing without waiting a real minute.
    pub fn with_window(specs: Vec<LaneSpec>, window: Duration) -> Self {
        Self {
            lanes: specs.into_iter().map(|s| Lane::new(s, window)).collect(),
            window,
        }
    }

    /// Build a replacement pool, carrying each kept key's spent budget and
    /// cooldown across the swap.
    ///
    /// Without this a settings save hands every key a fresh window, and the
    /// requests immediately after it exceed the provider's limit — which is
    /// precisely when someone is editing settings, because they are at capacity
    /// and adding keys. A key is matched by provider and secret, so renaming or
    /// reordering keeps its state and a genuinely new key starts clean.
    pub fn rebuild(&self, specs: Vec<LaneSpec>) -> Self {
        let lanes: Vec<Lane> = specs
            .into_iter()
            .map(|spec| {
                let lane = Lane::new(spec, self.window);
                if let Some(old) = self
                    .lanes
                    .iter()
                    .find(|l| l.provider == lane.provider && l.key == lane.key)
                {
                    lane.carry_from(old);
                }
                lane
            })
            .collect();
        Self {
            lanes,
            window: self.window,
        }
    }

    pub fn len(&self) -> usize {
        self.lanes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lanes.is_empty()
    }

    /// Aggregate requests-per-minute the whole pool can sustain.
    pub fn capacity_rpm(&self) -> usize {
        self.lanes.iter().map(|l| l.rpm).sum()
    }

    pub fn rpms(&self) -> Vec<usize> {
        self.lanes.iter().map(|l| l.rpm).collect()
    }

    pub fn lanes(&self) -> &[Lane] {
        &self.lanes
    }

    /// Sticky-lane hint: rendezvous (highest-random-weight) hash, so the lane
    /// maximizing `hash(session, lane identity)` wins. Pinning a conversation to
    /// one key keeps any upstream prefix cache warm across its turns.
    ///
    /// Weighting by the lane's *identity* rather than its index is what makes
    /// this survive pool changes: reordering lanes moves nothing, and adding or
    /// removing a key relocates only that key's share of conversations. Plain
    /// `hash % lanes` would remap nearly every conversation on any size change
    /// and dump every warm cache at once.
    ///
    /// Purely an optimization — correctness never depends on which key serves a
    /// request, so callers are free to spill elsewhere when this lane is full.
    pub fn affinity_lane(&self, session: u64) -> Option<usize> {
        self.affinity_among(session, 0..self.lanes.len())
    }

    /// Affinity restricted to `candidates`. Routing may narrow the eligible set
    /// to one provider or exclude lanes that already failed this request, and a
    /// conversation should stick within whatever set actually remains rather
    /// than losing its lane entirely.
    pub fn affinity_among(
        &self,
        session: u64,
        candidates: impl Iterator<Item = usize>,
    ) -> Option<usize> {
        candidates.max_by_key(|&i| {
            let lane = &self.lanes[i];
            let mut h = DefaultHasher::new();
            session.hash(&mut h);
            lane.provider.hash(&mut h);
            lane.key.hash(&mut h);
            h.finish()
        })
    }
}

/// A hot-swappable pool handle: settings can replace the pool without a restart.
pub type PoolHandle = std::sync::Arc<std::sync::RwLock<std::sync::Arc<Pool>>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Provider, ProviderKey, StoredConfig};

    #[test]
    fn window_allows_limit_then_blocks_then_recovers() {
        let base = Instant::now();
        let mut w = SlidingWindow::new(2, Duration::from_secs(60));
        assert!(w.try_acquire(base).is_ok());
        assert!(w.try_acquire(base + Duration::from_secs(1)).is_ok());
        let blocked = w.try_acquire(base + Duration::from_secs(2));
        assert_eq!(blocked.unwrap_err(), base + Duration::from_secs(60));
        assert!(w.try_acquire(base + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn window_zero_limit_never_grants() {
        let mut w = SlidingWindow::new(0, Duration::from_secs(60));
        assert!(w.try_acquire(Instant::now()).is_err());
    }

    fn provider(name: &str, rpm: usize, enabled: bool) -> Provider {
        Provider {
            name: name.into(),
            base_url: format!("http://{name}.test"),
            keys: vec![ProviderKey {
                key: format!("{name}-key"),
                enabled,
                rpm,
                owner: "admin".into(),
            }],
        }
    }

    #[test]
    fn pool_flattens_enabled_keys_across_providers() {
        let sc = StoredConfig {
            providers: vec![
                provider("nim", 40, true),
                provider("groq", 20, true),
                provider("off", 30, false),
            ],
            ..Default::default()
        };
        let pool = Pool::new(lane_specs(&sc));
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.capacity_rpm(), 60);
        assert_eq!(pool.rpms(), vec![40, 20]);
    }

    #[test]
    fn pool_lane_carries_provider_routing() {
        let sc = StoredConfig {
            providers: vec![provider("nim", 40, true)],
            ..Default::default()
        };
        let pool = Pool::new(lane_specs(&sc));
        let lane = &pool.lanes()[0];
        assert_eq!(lane.base_url, "http://nim.test");
        assert_eq!(lane.key, "nim-key");
        assert!(lane.try_acquire(Instant::now()).is_ok());
    }

    fn specs(n: usize) -> Vec<LaneSpec> {
        (0..n)
            .map(|i| LaneSpec {
                provider: "nim".into(),
                base_url: "http://nim.test".into(),
                key: format!("key-{i}"),
                rpm: 40,
            })
            .collect()
    }

    fn key_for(pool: &Pool, session: u64) -> String {
        pool.lanes()[pool.affinity_lane(session).unwrap()]
            .key
            .clone()
    }

    #[test]
    fn affinity_is_stable_for_the_same_session() {
        let pool = Pool::new(specs(5));
        let first = pool.affinity_lane(0x00C0FFEE).unwrap();
        for _ in 0..10 {
            assert_eq!(pool.affinity_lane(0x00C0FFEE), Some(first));
        }
    }

    #[test]
    fn affinity_spreads_sessions_over_every_lane() {
        let pool = Pool::new(specs(4));
        let mut hit = std::collections::HashSet::new();
        for s in 0..500u64 {
            hit.insert(pool.affinity_lane(s).unwrap());
        }
        assert_eq!(hit.len(), 4, "every lane should attract some sessions");
    }

    #[test]
    fn affinity_on_an_empty_pool_is_none() {
        assert_eq!(Pool::new(vec![]).affinity_lane(1), None);
    }

    /// The reason for rendezvous hashing over `hash % lanes`: adding a key must
    /// relocate only the new lane's share of conversations, not nearly all of
    /// them. Modulo would move ~5/6 here and dump every warm prefix cache at once.
    #[test]
    fn growing_the_pool_relocates_only_the_new_lanes_share() {
        let before = Pool::new(specs(5));
        let after = Pool::new(specs(6));
        let moved = (0..1200u64)
            .filter(|&s| key_for(&before, s) != key_for(&after, s))
            .count();
        assert!(
            moved < 300,
            "relocated {moved}/1200 sessions; expected ~1/6 (200)"
        );
    }

    #[test]
    fn a_benched_lane_is_out_of_rotation_until_its_cooldown_expires() {
        let pool = Pool::new(specs(1));
        let lane = &pool.lanes()[0];
        let now = Instant::now();
        lane.bench(now + Duration::from_secs(5));
        assert!(lane.benched(now));
        assert!(!lane.benched(now + Duration::from_secs(6)));
    }

    /// Two requests can discover the same sick key at once. The shorter of their
    /// two backoffs must not cancel the longer one already in force.
    #[test]
    fn benching_a_lane_again_never_shortens_its_cooldown() {
        let pool = Pool::new(specs(1));
        let lane = &pool.lanes()[0];
        let now = Instant::now();
        lane.bench(now + Duration::from_secs(30));
        lane.bench(now + Duration::from_secs(2));
        assert!(lane.benched(now + Duration::from_secs(10)));
    }

    /// A settings save must not hand every key a fresh rate window. Without
    /// carryover, editing anything at all lets the very next requests exceed the
    /// provider's limit — and editing settings is exactly what someone does while
    /// they are already at capacity and trying to add keys.
    #[test]
    fn a_rebuilt_pool_keeps_each_kept_keys_spent_budget() {
        let pool = Pool::with_window(specs(2), Duration::from_secs(60));
        let now = Instant::now();
        for _ in 0..3 {
            pool.lanes()[0].try_acquire(now).unwrap();
        }
        assert_eq!(pool.lanes()[0].load(now), 3);

        let rebuilt = pool.rebuild(specs(2));
        assert_eq!(
            rebuilt.lanes()[0].load(now),
            3,
            "the spent budget must survive the swap"
        );
        assert_eq!(
            rebuilt.lanes()[1].load(now),
            0,
            "an untouched key is unaffected"
        );
    }

    #[test]
    fn a_rebuilt_pool_keeps_a_benched_lane_benched() {
        let pool = Pool::with_window(specs(1), Duration::from_secs(60));
        let now = Instant::now();
        pool.lanes()[0].bench(now + Duration::from_secs(30));
        assert!(pool.rebuild(specs(1)).lanes()[0].benched(now));
    }

    #[test]
    fn a_newly_added_key_starts_with_a_clean_window() {
        let pool = Pool::with_window(specs(1), Duration::from_secs(60));
        let now = Instant::now();
        pool.lanes()[0].try_acquire(now).unwrap();
        let grown = pool.rebuild(specs(2));
        assert_eq!(
            grown.lanes()[0].load(now),
            1,
            "the existing key carries over"
        );
        assert_eq!(grown.lanes()[1].load(now), 0, "the new key is fresh");
    }

    /// Affinity is keyed on lane identity, not lane index, so a pool rebuild that
    /// reorders lanes (disabling a key, adding a provider) keeps every
    /// conversation on the key it was already warm on.
    #[test]
    fn reordering_lanes_relocates_nothing() {
        let pool = Pool::new(specs(4));
        let mut reordered = specs(4);
        reordered.reverse();
        let shuffled = Pool::new(reordered);
        for s in 0..300u64 {
            assert_eq!(
                key_for(&pool, s),
                key_for(&shuffled, s),
                "session {s} moved when only lane order changed"
            );
        }
    }
}
