//! Content-blind request metrics: counts, latencies, token totals, and per-lane
//! usage — sizes and counts only, never message content. Exposed as Prometheus
//! text (`render`) for scrapers and as structured JSON (`stats`) for the dashboard.
//! Labels are sanitized and the request-series count is capped so an untrusted
//! `model` can't explode the registry.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;

/// Beyond this many distinct (client, model, status) combos, new models collapse
/// to `other`.
const MAX_SERIES: usize = 500;

/// Keep a client-supplied label, or fold it into "other" once a map is full.
///
/// Model names arrive in the request body, so any map keyed on one grows as far
/// as a caller cares to push it. Every such map needs this, not just the first
/// one somebody remembered.
fn capped<V>(map: &HashMap<String, V>, label: String) -> String {
    if map.contains_key(&label) || map.len() < MAX_SERIES {
        label
    } else {
        "other".to_string()
    }
}

#[derive(Default)]
pub struct Metrics {
    /// (client, model, status) -> count
    requests: Mutex<HashMap<(String, String, String), u64>>,
    /// model -> (summed latency ms, count)
    latency: Mutex<HashMap<String, (u64, u64)>>,
    /// model -> (prompt tokens, completion tokens)
    tokens: Mutex<HashMap<String, (u64, u64)>>,
    /// provider (lane) -> count
    lanes: Mutex<HashMap<String, u64>>,
}

impl Metrics {
    pub fn record_request(&self, client: &str, model: &str, status: &str) {
        let (client, model, status) = (sanitize(client), sanitize(model), sanitize(status));
        let mut m = self.requests.lock().unwrap();
        let key = (client.clone(), model, status.clone());
        if !m.contains_key(&key) && m.len() >= MAX_SERIES {
            *m.entry((client, "other".to_string(), status)).or_insert(0) += 1;
            return;
        }
        *m.entry(key).or_insert(0) += 1;
    }

    pub fn record_latency(&self, model: &str, ms: u64) {
        let mut m = self.latency.lock().unwrap();
        let key = capped(&m, sanitize(model));
        let e = m.entry(key).or_insert((0, 0));
        e.0 += ms;
        e.1 += 1;
    }

    pub fn record_tokens(&self, model: &str, prompt: u64, completion: u64) {
        let mut m = self.tokens.lock().unwrap();
        let key = capped(&m, sanitize(model));
        let e = m.entry(key).or_insert((0, 0));
        e.0 += prompt;
        e.1 += completion;
    }

    pub fn record_lane(&self, provider: &str) {
        *self
            .lanes
            .lock()
            .unwrap()
            .entry(sanitize(provider))
            .or_insert(0) += 1;
    }

    /// Cumulative count of all requests recorded so far.
    pub fn total(&self) -> u64 {
        self.requests.lock().unwrap().values().sum()
    }

    /// Prometheus exposition for scrapers.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP sluice_requests_total Requests by client/model/status.\n");
        out.push_str("# TYPE sluice_requests_total counter\n");
        for ((client, model, status), count) in self.requests.lock().unwrap().iter() {
            out.push_str(&format!(
                "sluice_requests_total{{client=\"{client}\",model=\"{model}\",status=\"{status}\"}} {count}\n"
            ));
        }
        out.push_str("# HELP sluice_tokens_total Tokens by model and direction.\n");
        out.push_str("# TYPE sluice_tokens_total counter\n");
        for (model, (p, c)) in self.tokens.lock().unwrap().iter() {
            out.push_str(&format!(
                "sluice_tokens_total{{model=\"{model}\",direction=\"prompt\"}} {p}\n"
            ));
            out.push_str(&format!(
                "sluice_tokens_total{{model=\"{model}\",direction=\"completion\"}} {c}\n"
            ));
        }
        out.push_str("# HELP sluice_lane_requests_total Requests served per provider lane.\n");
        out.push_str("# TYPE sluice_lane_requests_total counter\n");
        for (lane, count) in self.lanes.lock().unwrap().iter() {
            out.push_str(&format!(
                "sluice_lane_requests_total{{provider=\"{lane}\"}} {count}\n"
            ));
        }
        out
    }

    /// Structured snapshot for the dashboard.
    pub fn stats(&self) -> Stats {
        let requests = self.requests.lock().unwrap();
        let latency = self.latency.lock().unwrap();
        let tokens = self.tokens.lock().unwrap();
        let lanes = self.lanes.lock().unwrap();

        let mut per_model: HashMap<String, u64> = HashMap::new();
        let mut per_client: HashMap<String, u64> = HashMap::new();
        let mut per_status: HashMap<String, u64> = HashMap::new();
        let mut total = 0u64;
        for ((client, model, status), count) in requests.iter() {
            *per_model.entry(model.clone()).or_insert(0) += count;
            *per_client.entry(client.clone()).or_insert(0) += count;
            *per_status.entry(status.clone()).or_insert(0) += count;
            total += count;
        }

        let models = per_model
            .iter()
            .map(|(model, &requests)| {
                let (lat_sum, lat_n) = latency.get(model).copied().unwrap_or((0, 0));
                let (pt, ct) = tokens.get(model).copied().unwrap_or((0, 0));
                ModelStat {
                    model: model.clone(),
                    requests,
                    avg_latency_ms: lat_sum.checked_div(lat_n).unwrap_or(0),
                    prompt_tokens: pt,
                    completion_tokens: ct,
                }
            })
            .collect();

        Stats {
            total,
            models,
            clients: per_client
                .into_iter()
                .map(|(client, requests)| ClientStat { client, requests })
                .collect(),
            statuses: per_status
                .into_iter()
                .map(|(status, count)| StatusStat { status, count })
                .collect(),
            lanes: lanes
                .iter()
                .map(|(provider, &requests)| LaneStat {
                    provider: provider.clone(),
                    requests,
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
pub struct Stats {
    pub total: u64,
    pub models: Vec<ModelStat>,
    pub clients: Vec<ClientStat>,
    pub statuses: Vec<StatusStat>,
    pub lanes: Vec<LaneStat>,
}

#[derive(Serialize)]
pub struct ModelStat {
    pub model: String,
    pub requests: u64,
    pub avg_latency_ms: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

#[derive(Serialize)]
pub struct ClientStat {
    pub client: String,
    pub requests: u64,
}

#[derive(Serialize)]
pub struct StatusStat {
    pub status: String,
    pub count: u64,
}

#[derive(Serialize)]
pub struct LaneStat {
    pub provider: String,
    pub requests: u64,
}

/// Reduce a label to a Prometheus-safe charset and cap its length. Filtering (not
/// escaping) keeps quotes/backslashes/newlines out of the exposition entirely.
pub fn sanitize(s: &str) -> String {
    let out: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':'))
        .take(64)
        .collect();
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_accumulate_per_series() {
        let m = Metrics::default();
        m.record_request("alice", "gpt", "200");
        m.record_request("alice", "gpt", "200");
        m.record_request("alice", "gpt", "429");
        let out = m.render();
        assert!(out.contains(r#"sluice_requests_total{client="alice",model="gpt",status="200"} 2"#));
        assert!(out.contains(r#"sluice_requests_total{client="alice",model="gpt",status="429"} 1"#));
    }

    #[test]
    fn labels_are_sanitized() {
        assert_eq!(sanitize("a\"b\nc"), "abc");
        assert_eq!(sanitize(""), "unknown");
        // Unsafe chars are filtered out, so nothing can break the exposition format.
        let m = Metrics::default();
        m.record_request("x", "evil\"\nmodel", "200");
        assert!(
            m.render().contains(r#"model="evilmodel""#),
            "got: {}",
            m.render()
        );
    }

    #[test]
    fn series_count_is_capped() {
        let m = Metrics::default();
        for i in 0..(MAX_SERIES + 50) {
            m.record_request("c", &format!("model-{i}"), "200");
        }
        let series = m
            .render()
            .lines()
            .filter(|l| l.starts_with("sluice_requests_total{"))
            .count();
        assert!(series <= MAX_SERIES + 1, "series not capped: {series}");
        assert!(m.render().contains(r#"model="other""#));
    }

    /// The model label comes straight out of a client's request body, so every
    /// map keyed on it is a memory-growth vector reachable by anyone holding a
    /// client key. `record_request` was capped and these two were not.
    #[test]
    fn latency_and_token_series_are_capped_too() {
        let m = Metrics::default();
        for i in 0..(MAX_SERIES + 200) {
            m.record_latency(&format!("model-{i}"), 10);
            m.record_tokens(&format!("model-{i}"), 1, 1);
        }
        assert!(
            m.latency.lock().unwrap().len() <= MAX_SERIES + 1,
            "latency map grew to {}",
            m.latency.lock().unwrap().len()
        );
        assert!(
            m.tokens.lock().unwrap().len() <= MAX_SERIES + 1,
            "token map grew to {}",
            m.tokens.lock().unwrap().len()
        );
    }

    #[test]
    fn stats_aggregate_by_dimension() {
        let m = Metrics::default();
        m.record_request("alice", "gpt", "200");
        m.record_request("bob", "gpt", "200");
        m.record_request("alice", "claude", "429");
        m.record_latency("gpt", 100);
        m.record_latency("gpt", 300);
        m.record_tokens("gpt", 10, 20);
        m.record_lane("nim");

        let s = m.stats();
        assert_eq!(s.total, 3);
        let gpt = s.models.iter().find(|x| x.model == "gpt").unwrap();
        assert_eq!(gpt.requests, 2);
        assert_eq!(gpt.avg_latency_ms, 200);
        assert_eq!(gpt.completion_tokens, 20);
        assert_eq!(
            s.clients
                .iter()
                .find(|c| c.client == "alice")
                .unwrap()
                .requests,
            2
        );
        assert_eq!(
            s.lanes
                .iter()
                .find(|l| l.provider == "nim")
                .unwrap()
                .requests,
            1
        );
    }
}
