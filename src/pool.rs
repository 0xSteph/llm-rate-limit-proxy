//! Provider-aware key pool. One "lane" per enabled API key across all configured
//! providers, each governed by an exact sliding-window limiter: N requests per
//! rolling window, matching a real provider's limiter rather than a burstable
//! token bucket.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::StoredConfig;

/// The rate window every provider limiter is measured over.
pub const WINDOW: Duration = Duration::from_secs(60);

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

    /// Grant a slot at `now`, or report when the next slot frees.
    /// `Ok(())` records a hit and grants; `Err(retry_at)` means saturated.
    pub fn try_acquire(&mut self, now: Instant) -> Result<(), Instant> {
        let cutoff = now.checked_sub(self.window);
        while let Some(&front) = self.hits.front() {
            match cutoff {
                Some(c) if front <= c => {
                    self.hits.pop_front();
                }
                _ => break,
            }
        }
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
}

impl Lane {
    fn new(spec: LaneSpec, window: Duration) -> Self {
        Self {
            limiter: Mutex::new(SlidingWindow::new(spec.rpm, window)),
            provider: spec.provider,
            base_url: spec.base_url,
            key: spec.key,
            rpm: spec.rpm,
        }
    }

    pub fn try_acquire(&self, now: Instant) -> Result<(), Instant> {
        self.limiter.lock().unwrap().try_acquire(now)
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
}

impl Pool {
    pub fn new(specs: Vec<LaneSpec>) -> Self {
        Self::with_window(specs, WINDOW)
    }

    /// Build with a custom window — tests use this to exercise pacing without
    /// waiting a real minute.
    pub fn with_window(specs: Vec<LaneSpec>, window: Duration) -> Self {
        Self {
            lanes: specs.into_iter().map(|s| Lane::new(s, window)).collect(),
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
}
