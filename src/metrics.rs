//! Content-blind request metrics: counts by (client, model, status) only — never any
//! message content. Rendered as Prometheus text. Labels are sanitized and the series
//! count is capped so an untrusted `model` value can't explode the registry.

use std::collections::HashMap;
use std::sync::Mutex;

/// Beyond this many distinct label combinations, new models collapse to `other`.
const MAX_SERIES: usize = 500;

#[derive(Default)]
pub struct Metrics {
    requests: Mutex<HashMap<(String, String, String), u64>>,
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

    /// Cumulative count of all requests recorded so far.
    pub fn total(&self) -> u64 {
        self.requests.lock().unwrap().values().sum()
    }

    pub fn render(&self) -> String {
        let m = self.requests.lock().unwrap();
        let mut out = String::new();
        out.push_str("# HELP sluice_requests_total Requests handled, by client/model/status.\n");
        out.push_str("# TYPE sluice_requests_total counter\n");
        for ((client, model, status), count) in m.iter() {
            out.push_str(&format!(
                "sluice_requests_total{{client=\"{client}\",model=\"{model}\",status=\"{status}\"}} {count}\n"
            ));
        }
        out
    }
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
}
