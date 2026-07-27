//! Exact-match response cache: an identical request returns the stored response
//! without touching an upstream or consuming a rate slot. Bounded (oldest entry
//! evicted when full) and per-entry TTL'd. Opt-in — disabled unless a TTL is set.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;

struct Entry {
    status: u16,
    content_type: Option<String>,
    body: Bytes,
    stored: Instant,
}

/// A cache hit, ready to relay to the client.
pub struct Cached {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Bytes,
}

pub struct Cache {
    ttl: Duration,
    max: usize,
    map: Mutex<HashMap<u64, Entry>>,
}

impl Cache {
    pub fn new(ttl: Duration, max: usize) -> Self {
        Self {
            ttl,
            max,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// A zero TTL means caching is switched off.
    pub fn enabled(&self) -> bool {
        !self.ttl.is_zero()
    }

    /// Cache key for a request: its path+query and exact body bytes.
    pub fn key(path: &str, body: &[u8]) -> u64 {
        let mut h = DefaultHasher::new();
        path.hash(&mut h);
        body.hash(&mut h);
        h.finish()
    }

    /// Fetch a live (non-expired) entry, evicting it if it has aged out.
    pub fn get(&self, key: u64) -> Option<Cached> {
        let mut map = self.map.lock().unwrap();
        if let Some(e) = map.get(&key) {
            if e.stored.elapsed() < self.ttl {
                return Some(Cached {
                    status: e.status,
                    content_type: e.content_type.clone(),
                    body: e.body.clone(),
                });
            }
            map.remove(&key);
        }
        None
    }

    pub fn put(&self, key: u64, status: u16, content_type: Option<String>, body: Bytes) {
        if !self.enabled() {
            return;
        }
        let mut map = self.map.lock().unwrap();
        if map.len() >= self.max && !map.contains_key(&key) {
            if let Some(oldest) = map.iter().min_by_key(|(_, e)| e.stored).map(|(k, _)| *k) {
                map.remove(&oldest);
            }
        }
        map.insert(
            key,
            Entry {
                status,
                content_type,
                body,
                stored: Instant::now(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_and_miss() {
        let c = Cache::new(Duration::from_secs(60), 10);
        let k = Cache::key("/v1/chat", b"body-a");
        assert!(c.get(k).is_none());
        c.put(
            k,
            200,
            Some("application/json".into()),
            Bytes::from_static(b"resp"),
        );
        let hit = c.get(k).unwrap();
        assert_eq!(hit.status, 200);
        assert_eq!(hit.body, Bytes::from_static(b"resp"));
        // A different body is a different key.
        assert!(c.get(Cache::key("/v1/chat", b"body-b")).is_none());
    }

    #[test]
    fn disabled_when_zero_ttl() {
        let c = Cache::new(Duration::ZERO, 10);
        assert!(!c.enabled());
        let k = Cache::key("/p", b"b");
        c.put(k, 200, None, Bytes::from_static(b"x"));
        assert!(c.get(k).is_none(), "disabled cache must not store");
    }

    #[test]
    fn expires_after_ttl() {
        let c = Cache::new(Duration::from_millis(1), 10);
        let k = Cache::key("/p", b"b");
        c.put(k, 200, None, Bytes::from_static(b"x"));
        std::thread::sleep(Duration::from_millis(6));
        assert!(c.get(k).is_none(), "entry should have expired");
    }

    #[test]
    fn bounded_capacity() {
        let c = Cache::new(Duration::from_secs(60), 2);
        for i in 0..5u8 {
            c.put(Cache::key("/p", &[i]), 200, None, Bytes::from_static(b"x"));
        }
        assert!(c.map.lock().unwrap().len() <= 2, "cache exceeded its bound");
    }
}
