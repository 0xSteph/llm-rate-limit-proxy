//! Global FIFO dispatcher: hands out rate slots across the pool in arrival order,
//! waiting on the soonest-free lane when every lane is saturated. Because the head
//! of the queue holds the fairness gate while it waits, no later request can jump
//! ahead of an earlier one.

use std::time::{Duration, Instant};

use crate::config::Protocol;
use crate::pool::PoolHandle;

/// A granted rate slot: which lane won, and where to send the request.
pub struct Permit {
    pub lane_idx: usize,
    pub provider: String,
    pub base_url: String,
    pub key: String,
    pub protocol: Protocol,
}

pub struct Dispatcher {
    pool: PoolHandle,
    /// Tokio's mutex is fair, so waiters are served strictly in arrival order.
    gate: tokio::sync::Mutex<()>,
}

impl Dispatcher {
    pub fn new(pool: PoolHandle) -> Self {
        Self {
            pool,
            gate: tokio::sync::Mutex::new(()),
        }
    }

    /// Acquire any rate slot, blocking until one is available. Convenience for
    /// callers that don't care which provider or lane serves them.
    pub async fn acquire(&self) -> Permit {
        self.acquire_for(None, &[], None, None)
            .await
            .expect("acquire on a non-empty pool")
    }

    /// Acquire a slot on a lane matching `provider` (any provider if `None`) and not
    /// in `exclude`. Blocks while eligible lanes are saturated; returns `None`
    /// immediately when *no* eligible lane exists, so the caller can fall through to
    /// the next routing target. Fair (FIFO) via the gate; a dropped caller yields.
    pub async fn acquire_for(
        &self,
        provider: Option<&str>,
        exclude: &[usize],
        session: Option<u64>,
        protocol: Option<Protocol>,
    ) -> Option<Permit> {
        let _fifo = self.gate.lock().await;
        loop {
            let pool = self.pool.read().unwrap().clone();
            let now = Instant::now();
            let mut soonest: Option<Instant> = None;
            let mut eligible = false;
            // (spent budget, lane index) for every eligible lane with room left.
            let mut with_room: Vec<(usize, usize)> = Vec::new();
            for (idx, lane) in pool.lanes().iter().enumerate() {
                // Protocol is a hard filter, not a preference: this proxy forwards
                // bodies unchanged, so an Anthropic-shaped request sent to an
                // OpenAI upstream earns a 400 no matter which key serves it.
                if provider.is_some_and(|p| lane.provider != p)
                    || protocol.is_some_and(|w| lane.protocol != w)
                    || exclude.contains(&idx)
                {
                    continue;
                }
                eligible = true;
                // A lane the provider told us to back off from stays out of
                // rotation until its cooldown ends, but still counts as eligible
                // so an all-benched pool waits instead of reporting itself empty.
                if let Some(until) = lane.cooldown_ends(now) {
                    soonest = Some(soonest.map_or(until, |s: Instant| s.min(until)));
                    continue;
                }
                let load = lane.load(now);
                if load < lane.rpm {
                    with_room.push((load, idx));
                } else if let Err(retry_at) = lane.try_acquire(now) {
                    // A saturated lane records nothing, so this only reads its clock.
                    soonest = Some(soonest.map_or(retry_at, |s: Instant| s.min(retry_at)));
                }
            }
            // A conversation keeps its own lane while that lane has budget, so the
            // upstream prefix cache stays warm; anything else takes the emptiest
            // lane, spreading concurrent requests instead of stacking on lane 0.
            // Ties break to the lower index, keeping the choice deterministic.
            let choice = session
                .and_then(|s| pool.affinity_among(s, with_room.iter().map(|&(_, i)| i)))
                .or_else(|| with_room.iter().min().map(|&(_, i)| i));
            if let Some(idx) = choice {
                let lane = &pool.lanes()[idx];
                if lane.try_acquire(now).is_ok() {
                    return Some(Permit {
                        lane_idx: idx,
                        provider: lane.provider.clone(),
                        base_url: lane.base_url.clone(),
                        key: lane.key.clone(),
                        protocol: lane.protocol,
                    });
                }
            }
            if !eligible {
                return None;
            }
            let wait = match soonest {
                Some(t) => t.saturating_duration_since(Instant::now()),
                None => Duration::from_millis(100),
            };
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{LaneSpec, Pool};
    use std::sync::{Arc, RwLock};

    fn spec(name: &str, rpm: usize) -> LaneSpec {
        LaneSpec {
            provider: name.into(),
            base_url: format!("http://{name}.test"),
            key: format!("{name}-key"),
            rpm,
            protocol: Default::default(),
        }
    }

    fn handle(pool: Pool) -> PoolHandle {
        Arc::new(RwLock::new(Arc::new(pool)))
    }

    #[tokio::test]
    async fn grants_immediately_and_spreads_across_lanes() {
        let pool = Pool::with_window(vec![spec("a", 1), spec("b", 1)], Duration::from_millis(300));
        let d = Dispatcher::new(handle(pool));
        let t0 = Instant::now();
        let p1 = d.acquire().await;
        let p2 = d.acquire().await;
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "both should be immediate"
        );
        assert_ne!(
            p1.lane_idx, p2.lane_idx,
            "second should spill to the other lane"
        );
    }

    #[tokio::test]
    async fn affinity_pins_a_session_to_one_lane_then_spills_when_full() {
        let pool = Pool::with_window(vec![spec("a", 2), spec("b", 2)], Duration::from_secs(60));
        let d = Dispatcher::new(handle(pool));
        let s = Some(0xBEEFu64);
        let first = d.acquire_for(None, &[], s, None).await.unwrap().lane_idx;
        let second = d.acquire_for(None, &[], s, None).await.unwrap().lane_idx;
        assert_eq!(first, second, "a session should stay on its own lane");
        // That lane is now at its rpm of 2, so the third has to spill.
        let third = d.acquire_for(None, &[], s, None).await.unwrap().lane_idx;
        assert_ne!(third, first, "a full affinity lane must spill, not block");
    }

    #[tokio::test]
    async fn spillover_spreads_across_lanes_instead_of_filling_the_first() {
        // Both lanes have room throughout, so a first-fit scan would put every
        // request on lane 0 and leave key 1 idle. Least-loaded alternates.
        let pool = Pool::with_window(vec![spec("a", 3), spec("b", 3)], Duration::from_secs(60));
        let d = Dispatcher::new(handle(pool));
        let mut on_lane = [0usize; 2];
        for _ in 0..4 {
            on_lane[d.acquire().await.lane_idx] += 1;
        }
        assert_eq!(on_lane, [2, 2], "load should spread, not fill lane 0 first");
    }

    #[tokio::test]
    async fn a_benched_lane_is_skipped_for_a_healthy_one() {
        let pool = Pool::with_window(vec![spec("a", 40), spec("b", 40)], Duration::from_secs(60));
        pool.lanes()[0].bench(Instant::now() + Duration::from_secs(30));
        let d = Dispatcher::new(handle(pool));
        for _ in 0..3 {
            assert_eq!(
                d.acquire().await.lane_idx,
                1,
                "a lane the provider told us to back off from must be routed around"
            );
        }
    }

    #[tokio::test]
    async fn every_lane_benched_waits_out_the_cooldown_rather_than_failing() {
        let pool = Pool::with_window(vec![spec("a", 40)], Duration::from_secs(60));
        pool.lanes()[0].bench(Instant::now() + Duration::from_millis(200));
        let d = Dispatcher::new(handle(pool));
        let t0 = Instant::now();
        assert_eq!(d.acquire().await.lane_idx, 0);
        assert!(
            t0.elapsed() >= Duration::from_millis(150),
            "a benched pool should wait, not report itself empty"
        );
    }

    #[tokio::test]
    async fn paces_when_saturated() {
        let pool = Pool::with_window(vec![spec("a", 1)], Duration::from_millis(300));
        let d = Dispatcher::new(handle(pool));
        let t0 = Instant::now();
        let _p1 = d.acquire().await; // immediate
        let _p2 = d.acquire().await; // must wait ~window for the lane to free
        assert!(
            t0.elapsed() >= Duration::from_millis(250),
            "second grant should be paced by the window"
        );
    }
}
