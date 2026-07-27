//! Metrics history: periodic snapshots of the cumulative request total, persisted
//! to a JSONL file so range views survive restarts. Snapshots older than the
//! retention window are pruned on each append.

use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// Default seconds between snapshots (5 minutes). Overridable for tests.
pub const SAMPLE_SECS: u64 = 300;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct Snapshot {
    /// Unix seconds.
    pub t: u64,
    /// Cumulative request count at that time.
    pub total: u64,
}

pub struct History {
    path: Option<PathBuf>,
    retention_secs: u64,
    snapshots: RwLock<Vec<Snapshot>>,
}

impl History {
    /// Load prior snapshots from `path` (if any) and set retention (`0` days = keep
    /// forever).
    pub fn load(path: Option<PathBuf>, retention_days: u32) -> Self {
        let retention_secs = if retention_days == 0 {
            u64::MAX
        } else {
            retention_days as u64 * 86_400
        };
        let mut snapshots = Vec::new();
        if let Some(p) = &path {
            if let Ok(content) = std::fs::read_to_string(p) {
                for line in content.lines() {
                    if let Ok(s) = serde_json::from_str::<Snapshot>(line) {
                        snapshots.push(s);
                    }
                }
            }
        }
        History {
            path,
            retention_secs,
            snapshots: RwLock::new(snapshots),
        }
    }

    /// Append a snapshot, prune expired ones, and persist. Retention keeps the file
    /// small (≈8.6k lines at 30 days × 5-min), so a full rewrite each tick is cheap.
    pub fn append(&self, t: u64, total: u64) {
        let mut snaps = self.snapshots.write().unwrap();
        snaps.push(Snapshot { t, total });
        let cutoff = t.saturating_sub(self.retention_secs);
        snaps.retain(|s| s.t >= cutoff);
        if let Some(p) = &self.path {
            let mut out = String::new();
            for s in snaps.iter() {
                if let Ok(line) = serde_json::to_string(s) {
                    out.push_str(&line);
                    out.push('\n');
                }
            }
            let _ = std::fs::write(p, out);
        }
    }

    /// Snapshots within `[from, to]`, downsampled to at most `max` points.
    pub fn range(&self, from: u64, to: u64, max: usize) -> Vec<Snapshot> {
        let snaps = self.snapshots.read().unwrap();
        let filtered: Vec<Snapshot> = snaps
            .iter()
            .copied()
            .filter(|s| s.t >= from && s.t <= to)
            .collect();
        downsample(filtered, max)
    }
}

fn downsample(v: Vec<Snapshot>, max: usize) -> Vec<Snapshot> {
    if max == 0 || v.len() <= max {
        return v;
    }
    let step = (v.len() / max).max(1);
    v.into_iter().step_by(step).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_range_roundtrips() {
        let h = History::load(None, 30);
        h.append(100, 5);
        h.append(200, 9);
        let all = h.range(0, 1000, 100);
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].total, 9);
        // Range filtering.
        assert_eq!(h.range(150, 1000, 100).len(), 1);
    }

    #[test]
    fn prunes_beyond_retention() {
        let h = History::load(None, 1); // 1 day = 86400s
        h.append(1_000, 1);
        h.append(1_000 + 200_000, 2); // 200k s later — first is now expired
        let all = h.range(0, u64::MAX, 100);
        assert_eq!(all.len(), 1, "old snapshot should have been pruned");
        assert_eq!(all[0].total, 2);
    }

    #[test]
    fn persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.jsonl");
        {
            let h = History::load(Some(path.clone()), 30);
            h.append(10, 1);
            h.append(20, 4);
        }
        let reloaded = History::load(Some(path), 30);
        assert_eq!(reloaded.range(0, 1000, 100).len(), 2);
    }

    #[test]
    fn downsamples_to_max() {
        let h = History::load(None, 0);
        for i in 0..1000 {
            h.append(i, i);
        }
        assert!(h.range(0, u64::MAX, 50).len() <= 50);
    }
}
