//! Content-blind request metrics: counts, latencies, token totals, and per-lane
//! usage — sizes and counts only, never message content. Exposed as Prometheus
//! text (`render`) for scrapers and as structured JSON (`stats`) for the dashboard.
//! Labels are sanitized and the request-series count is capped so an untrusted
//! `model` can't explode the registry.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// A named summary map, as exposed to Prometheus.
type SummaryMap = Mutex<HashMap<String, Summary>>;

/// sum/count/max for a distribution.
///
/// Deliberately not a bucketed histogram: those need bucket boundaries chosen
/// per metric and get them wrong, and what an operator asks first is "what is
/// it normally, and how bad does it get". Prometheus reads `_sum` and `_count`
/// as a summary; the dashboard shows the average and the worst case.
#[derive(Default, Clone, Copy, Serialize)]
pub struct Summary {
    pub sum: u64,
    pub count: u64,
    pub max: u64,
}

impl Summary {
    fn add(&mut self, v: u64) {
        self.sum += v;
        self.count += 1;
        if v > self.max {
            self.max = v;
        }
    }
    pub fn avg(&self) -> u64 {
        self.sum.checked_div(self.count).unwrap_or(0)
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

    /// model -> time from sending upstream to the first streamed byte. The
    /// number that moves first when a provider starts degrading.
    ttft_ms: SummaryMap,
    /// model -> generation speed, completion tokens per second.
    tok_per_sec: SummaryMap,
    /// Time spent waiting for a rate slot, across all models. Rising queue wait
    /// means the pool is the constraint; flat wait with rising latency means the
    /// provider is.
    queue_wait_ms: Mutex<Summary>,
    /// (model, reason) -> count. `length` is truncation — an answer cut off
    /// mid-thought, which looks like a bad model until you see the reason.
    finish: Mutex<HashMap<(String, String), u64>>,
    /// model -> (tool calls emitted, reasoning tokens)
    extras: Mutex<HashMap<String, (u64, u64)>>,
    /// What the harness asked for: conversation depth, tools offered, output
    /// budget, sampling temperature (x100, since these are integers).
    shape: Mutex<HashMap<String, [Summary; 4]>>,
    /// Things that happened to requests rather than to models: retries, benched
    /// lanes, sheds, refusals, deadline expiries.
    events: Mutex<HashMap<String, u64>>,
    /// streaming vs buffered
    streamed: AtomicU64,
    buffered: AtomicU64,
    /// Requests in flight right now.
    active: AtomicU64,
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

    /// Time from sending upstream to the first byte back. This is the number
    /// that moves first when a provider degrades — total latency also moves, but
    /// only after the whole generation finishes.
    pub fn record_ttft(&self, model: &str, ms: u64) {
        let mut m = self.ttft_ms.lock().unwrap();
        let key = capped(&m, sanitize(model));
        m.entry(key).or_default().add(ms);
    }

    /// Generation speed. Recorded only when both the token count and the elapsed
    /// time are real, so a cached or empty answer cannot invent a huge rate.
    pub fn record_speed(&self, model: &str, completion_tokens: u64, gen_ms: u64) {
        if completion_tokens == 0 || gen_ms == 0 {
            return;
        }
        let per_sec = completion_tokens * 1000 / gen_ms;
        let mut m = self.tok_per_sec.lock().unwrap();
        let key = capped(&m, sanitize(model));
        m.entry(key).or_default().add(per_sec);
    }

    /// How long a request waited for a rate slot. Distinguishes "our pool is the
    /// bottleneck" from "the provider is slow", which look identical end to end.
    pub fn record_queue_wait(&self, ms: u64) {
        self.queue_wait_ms.lock().unwrap().add(ms);
    }

    /// Why a generation stopped. `length` means truncated at the output cap.
    pub fn record_finish(&self, model: &str, reason: &str) {
        let mut m = self.finish.lock().unwrap();
        let model = sanitize(model);
        let key = (model.clone(), sanitize(reason));
        if !m.contains_key(&key) && m.len() >= MAX_SERIES {
            return;
        }
        *m.entry(key).or_insert(0) += 1;
    }

    pub fn record_extras(&self, model: &str, tool_calls: u64, reasoning_tokens: u64) {
        if tool_calls == 0 && reasoning_tokens == 0 {
            return;
        }
        let mut m = self.extras.lock().unwrap();
        let key = capped(&m, sanitize(model));
        let e = m.entry(key).or_insert((0, 0));
        e.0 += tool_calls;
        e.1 += reasoning_tokens;
    }

    /// What the caller asked for. Content-blind: counts and sizes, never text.
    pub fn record_shape(
        &self,
        client: &str,
        messages: u64,
        tools: u64,
        max_tokens: u64,
        temperature_x100: u64,
    ) {
        let mut m = self.shape.lock().unwrap();
        let key = capped(&m, sanitize(client));
        let e = m.entry(key).or_default();
        e[0].add(messages);
        e[1].add(tools);
        e[2].add(max_tokens);
        e[3].add(temperature_x100);
    }

    /// Something happened to a request rather than to a model: a retry, a
    /// benched lane, a shed, a refusal, a deadline.
    pub fn record_event(&self, kind: &str) {
        let mut m = self.events.lock().unwrap();
        let key = capped(&m, sanitize(kind));
        *m.entry(key).or_insert(0) += 1;
    }

    pub fn record_stream_mix(&self, streaming: bool) {
        if streaming {
            self.streamed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.buffered.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Returns a guard so the gauge cannot leak: a request that ends by any path
    /// still decrements.
    pub fn track_active(&self) -> ActiveGuard<'_> {
        self.active.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(&self.active)
    }

    /// Cumulative count of all requests recorded so far.
    pub fn total(&self) -> u64 {
        self.requests.lock().unwrap().values().sum()
    }

    /// Prometheus exposition for scrapers.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "# HELP llm_rate_limit_proxy_requests_total Requests by client/model/status.\n",
        );
        out.push_str("# TYPE llm_rate_limit_proxy_requests_total counter\n");
        for ((client, model, status), count) in self.requests.lock().unwrap().iter() {
            out.push_str(&format!(
                "llm_rate_limit_proxy_requests_total{{client=\"{client}\",model=\"{model}\",status=\"{status}\"}} {count}\n"
            ));
        }
        out.push_str("# HELP llm_rate_limit_proxy_tokens_total Tokens by model and direction.\n");
        out.push_str("# TYPE llm_rate_limit_proxy_tokens_total counter\n");
        for (model, (p, c)) in self.tokens.lock().unwrap().iter() {
            out.push_str(&format!(
                "llm_rate_limit_proxy_tokens_total{{model=\"{model}\",direction=\"prompt\"}} {p}\n"
            ));
            out.push_str(&format!(
                "llm_rate_limit_proxy_tokens_total{{model=\"{model}\",direction=\"completion\"}} {c}\n"
            ));
        }
        out.push_str(
            "# HELP llm_rate_limit_proxy_lane_requests_total Requests served per provider lane.\n",
        );
        out.push_str("# TYPE llm_rate_limit_proxy_lane_requests_total counter\n");
        for (lane, count) in self.lanes.lock().unwrap().iter() {
            out.push_str(&format!(
                "llm_rate_limit_proxy_lane_requests_total{{provider=\"{lane}\"}} {count}\n"
            ));
        }

        // Summaries are exposed as _sum/_count pairs, which is what Prometheus
        // expects and what lets a scraper compute rate()-based averages itself.
        let summaries: [(&str, &str, &SummaryMap); 2] = [
            (
                "llm_rate_limit_proxy_ttft_ms",
                "Time to first byte from upstream.",
                &self.ttft_ms,
            ),
            (
                "llm_rate_limit_proxy_tokens_per_second",
                "Generation speed.",
                &self.tok_per_sec,
            ),
        ];
        for (name, help, map) in summaries {
            out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} summary\n"));
            for (model, sm) in map.lock().unwrap().iter() {
                out.push_str(&format!("{name}_sum{{model=\"{model}\"}} {}\n", sm.sum));
                out.push_str(&format!("{name}_count{{model=\"{model}\"}} {}\n", sm.count));
                out.push_str(&format!("{name}_max{{model=\"{model}\"}} {}\n", sm.max));
            }
        }

        let q = *self.queue_wait_ms.lock().unwrap();
        out.push_str("# HELP llm_rate_limit_proxy_queue_wait_ms Time waiting for a rate slot.\n");
        out.push_str("# TYPE llm_rate_limit_proxy_queue_wait_ms summary\n");
        out.push_str(&format!(
            "llm_rate_limit_proxy_queue_wait_ms_sum {}\n",
            q.sum
        ));
        out.push_str(&format!(
            "llm_rate_limit_proxy_queue_wait_ms_count {}\n",
            q.count
        ));
        out.push_str(&format!(
            "llm_rate_limit_proxy_queue_wait_ms_max {}\n",
            q.max
        ));

        out.push_str(
            "# HELP llm_rate_limit_proxy_finish_reason_total How generations ended; 'length' is truncation.\n",
        );
        out.push_str("# TYPE llm_rate_limit_proxy_finish_reason_total counter\n");
        for ((model, reason), n) in self.finish.lock().unwrap().iter() {
            out.push_str(&format!(
                "llm_rate_limit_proxy_finish_reason_total{{model=\"{model}\",reason=\"{reason}\"}} {n}\n"
            ));
        }

        out.push_str(
            "# HELP llm_rate_limit_proxy_model_extras_total Tool calls emitted and reasoning tokens burned.\n",
        );
        out.push_str("# TYPE llm_rate_limit_proxy_model_extras_total counter\n");
        for (model, (tools, reasoning)) in self.extras.lock().unwrap().iter() {
            out.push_str(&format!(
                "llm_rate_limit_proxy_model_extras_total{{model=\"{model}\",kind=\"tool_calls\"}} {tools}\n"
            ));
            out.push_str(&format!(
                "llm_rate_limit_proxy_model_extras_total{{model=\"{model}\",kind=\"reasoning_tokens\"}} {reasoning}\n"
            ));
        }

        out.push_str("# HELP llm_rate_limit_proxy_request_shape What harnesses ask for: depth, tools, output cap, temperature x100.\n");
        out.push_str("# TYPE llm_rate_limit_proxy_request_shape summary\n");
        for (client, s) in self.shape.lock().unwrap().iter() {
            for (dim, sm) in ["messages", "tools", "max_tokens", "temperature_x100"]
                .iter()
                .zip(s.iter())
            {
                out.push_str(&format!(
                    "llm_rate_limit_proxy_request_shape_sum{{client=\"{client}\",dim=\"{dim}\"}} {}\n",
                    sm.sum
                ));
                out.push_str(&format!(
                    "llm_rate_limit_proxy_request_shape_count{{client=\"{client}\",dim=\"{dim}\"}} {}\n",
                    sm.count
                ));
            }
        }

        out.push_str(
            "# HELP llm_rate_limit_proxy_events_total Retries, benched lanes, sheds, refusals, deadlines.\n",
        );
        out.push_str("# TYPE llm_rate_limit_proxy_events_total counter\n");
        for (kind, n) in self.events.lock().unwrap().iter() {
            out.push_str(&format!(
                "llm_rate_limit_proxy_events_total{{kind=\"{kind}\"}} {n}\n"
            ));
        }

        out.push_str("# HELP llm_rate_limit_proxy_stream_requests_total Streaming vs buffered.\n");
        out.push_str("# TYPE llm_rate_limit_proxy_stream_requests_total counter\n");
        out.push_str(&format!(
            "llm_rate_limit_proxy_stream_requests_total{{stream=\"true\"}} {}\n",
            self.streamed.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "llm_rate_limit_proxy_stream_requests_total{{stream=\"false\"}} {}\n",
            self.buffered.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP llm_rate_limit_proxy_active_requests Requests in flight right now.\n");
        out.push_str("# TYPE llm_rate_limit_proxy_active_requests gauge\n");
        out.push_str(&format!(
            "llm_rate_limit_proxy_active_requests {}\n",
            self.active.load(Ordering::Relaxed)
        ));
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

        let ttft = self.ttft_ms.lock().unwrap();
        let speed = self.tok_per_sec.lock().unwrap();
        let finish = self.finish.lock().unwrap();
        let extras = self.extras.lock().unwrap();

        let models = per_model
            .iter()
            .map(|(model, &requests)| {
                let (lat_sum, lat_n) = latency.get(model).copied().unwrap_or((0, 0));
                let (pt, ct) = tokens.get(model).copied().unwrap_or((0, 0));
                let t = ttft.get(model).copied().unwrap_or_default();
                let sp = speed.get(model).copied().unwrap_or_default();
                let (tools, reasoning) = extras.get(model).copied().unwrap_or((0, 0));
                // Truncation rate is the actionable one: a model that keeps
                // stopping at the output cap is being cut off, not failing.
                let truncated = finish
                    .get(&(model.clone(), "length".to_string()))
                    .copied()
                    .unwrap_or(0);
                ModelStat {
                    model: model.clone(),
                    requests,
                    avg_latency_ms: lat_sum.checked_div(lat_n).unwrap_or(0),
                    prompt_tokens: pt,
                    completion_tokens: ct,
                    avg_ttft_ms: t.avg(),
                    max_ttft_ms: t.max,
                    avg_tokens_per_sec: sp.avg(),
                    truncated,
                    tool_calls: tools,
                    reasoning_tokens: reasoning,
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
            queue_wait: *self.queue_wait_ms.lock().unwrap(),
            active: self.active.load(Ordering::Relaxed),
            streamed: self.streamed.load(Ordering::Relaxed),
            buffered: self.buffered.load(Ordering::Relaxed),
            events: self
                .events
                .lock()
                .unwrap()
                .iter()
                .map(|(kind, &count)| EventStat {
                    kind: kind.clone(),
                    count,
                })
                .collect(),
            shape: self
                .shape
                .lock()
                .unwrap()
                .iter()
                .map(|(client, s)| ShapeStat {
                    client: client.clone(),
                    avg_messages: s[0].avg(),
                    avg_tools: s[1].avg(),
                    avg_max_tokens: s[2].avg(),
                    avg_temperature_x100: s[3].avg(),
                })
                .collect(),
        }
    }
}

/// Holds the in-flight count for one request; decrements on drop.
pub struct ActiveGuard<'a>(&'a AtomicU64);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Serialize)]
pub struct Stats {
    pub total: u64,
    pub models: Vec<ModelStat>,
    pub clients: Vec<ClientStat>,
    pub statuses: Vec<StatusStat>,
    pub lanes: Vec<LaneStat>,
    pub queue_wait: Summary,
    pub active: u64,
    pub streamed: u64,
    pub buffered: u64,
    pub events: Vec<EventStat>,
    pub shape: Vec<ShapeStat>,
}

#[derive(Serialize)]
pub struct EventStat {
    pub kind: String,
    pub count: u64,
}

#[derive(Serialize)]
pub struct ShapeStat {
    pub client: String,
    pub avg_messages: u64,
    pub avg_tools: u64,
    pub avg_max_tokens: u64,
    pub avg_temperature_x100: u64,
}

#[derive(Serialize)]
pub struct ModelStat {
    pub model: String,
    pub requests: u64,
    pub avg_latency_ms: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub avg_ttft_ms: u64,
    pub max_ttft_ms: u64,
    pub avg_tokens_per_sec: u64,
    /// Generations that stopped at the output cap rather than finishing.
    pub truncated: u64,
    pub tool_calls: u64,
    pub reasoning_tokens: u64,
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
        assert!(out.contains(
            r#"llm_rate_limit_proxy_requests_total{client="alice",model="gpt",status="200"} 2"#
        ));
        assert!(out.contains(
            r#"llm_rate_limit_proxy_requests_total{client="alice",model="gpt",status="429"} 1"#
        ));
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
            .filter(|l| l.starts_with("llm_rate_limit_proxy_requests_total{"))
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
    fn ttft_and_speed_surface_per_model() {
        let m = Metrics::default();
        m.record_request("c", "fast", "200");
        m.record_ttft("fast", 120);
        m.record_ttft("fast", 480);
        // 200 completion tokens in 2s = 100/sec
        m.record_speed("fast", 200, 2000);
        let s = m.stats();
        let f = s.models.iter().find(|x| x.model == "fast").unwrap();
        assert_eq!(f.avg_ttft_ms, 300, "average of 120 and 480");
        assert_eq!(f.max_ttft_ms, 480, "worst case is what you get paged for");
        assert_eq!(f.avg_tokens_per_sec, 100);
    }

    /// A zero-token or zero-duration answer must not invent an infinite rate.
    #[test]
    fn speed_ignores_measurements_it_cannot_trust() {
        let m = Metrics::default();
        m.record_request("c", "m", "200");
        m.record_speed("m", 0, 1000);
        m.record_speed("m", 100, 0);
        assert_eq!(m.stats().models[0].avg_tokens_per_sec, 0);
    }

    /// Truncation looks like a bad model until you can see the reason.
    #[test]
    fn truncation_is_counted_separately_from_completion() {
        let m = Metrics::default();
        m.record_request("c", "m", "200");
        m.record_finish("m", "stop");
        m.record_finish("m", "length");
        m.record_finish("m", "length");
        assert_eq!(m.stats().models[0].truncated, 2);
    }

    #[test]
    fn the_active_gauge_cannot_leak() {
        let m = Metrics::default();
        {
            let _a = m.track_active();
            let _b = m.track_active();
            assert_eq!(m.stats().active, 2);
        }
        assert_eq!(m.stats().active, 0, "guards must decrement on drop");
    }

    #[test]
    fn events_and_shape_reach_the_dashboard() {
        let m = Metrics::default();
        m.record_event("retry");
        m.record_event("retry");
        m.record_event("shed");
        m.record_queue_wait(250);
        m.record_shape("opencode", 12, 4, 4096, 20);
        m.record_stream_mix(true);
        m.record_stream_mix(false);
        let s = m.stats();
        assert_eq!(
            s.events.iter().find(|e| e.kind == "retry").unwrap().count,
            2
        );
        assert_eq!(s.queue_wait.avg(), 250);
        assert_eq!(s.shape[0].avg_messages, 12);
        assert_eq!(s.shape[0].avg_temperature_x100, 20);
        assert_eq!((s.streamed, s.buffered), (1, 1));
    }

    #[test]
    fn every_new_series_is_capped_too() {
        let m = Metrics::default();
        for i in 0..(MAX_SERIES + 200) {
            m.record_ttft(&format!("model-{i}"), 1);
            m.record_speed(&format!("model-{i}"), 10, 100);
            m.record_extras(&format!("model-{i}"), 1, 1);
            m.record_shape(&format!("client-{i}"), 1, 1, 1, 1);
            m.record_event(&format!("kind-{i}"));
            m.record_finish(&format!("model-{i}"), "stop");
        }
        let cap = MAX_SERIES + 1;
        assert!(m.ttft_ms.lock().unwrap().len() <= cap);
        assert!(m.tok_per_sec.lock().unwrap().len() <= cap);
        assert!(m.extras.lock().unwrap().len() <= cap);
        assert!(m.shape.lock().unwrap().len() <= cap);
        assert!(m.events.lock().unwrap().len() <= cap);
        assert!(m.finish.lock().unwrap().len() <= cap);
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
