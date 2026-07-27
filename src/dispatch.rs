//! Global FIFO dispatcher: hands out rate slots across the pool in arrival order,
//! waiting on the soonest-free lane when every lane is saturated. Because the head
//! of the queue holds the fairness gate while it waits, no later request can jump
//! ahead of an earlier one.

use std::time::{Duration, Instant};

use crate::pool::PoolHandle;

/// A granted rate slot: which lane won, and where to send the request.
pub struct Permit {
    pub lane_idx: usize,
    pub provider: String,
    pub base_url: String,
    pub key: String,
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

    /// Acquire a rate slot, blocking until one is available. Dropping the returned
    /// future while still queued relinquishes the caller's place in line.
    pub async fn acquire(&self) -> Permit {
        self.acquire_excluding(&[]).await
    }

    /// Like [`acquire`], but skips the given lane indices — used to fail a request
    /// over to a *different* key after one lane returned a retryable error. Callers
    /// must leave at least one lane unexcluded.
    pub async fn acquire_excluding(&self, exclude: &[usize]) -> Permit {
        let _fifo = self.gate.lock().await;
        loop {
            let pool = self.pool.read().unwrap().clone();
            let now = Instant::now();
            let mut soonest: Option<Instant> = None;
            for (idx, lane) in pool.lanes().iter().enumerate() {
                if exclude.contains(&idx) {
                    continue;
                }
                match lane.try_acquire(now) {
                    Ok(()) => {
                        return Permit {
                            lane_idx: idx,
                            provider: lane.provider.clone(),
                            base_url: lane.base_url.clone(),
                            key: lane.key.clone(),
                        };
                    }
                    Err(retry_at) => {
                        soonest = Some(soonest.map_or(retry_at, |s| s.min(retry_at)));
                    }
                }
            }
            // No eligible lane ready: sleep until the soonest one frees (or briefly,
            // if the pool is momentarily empty and settings may still fill it).
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
