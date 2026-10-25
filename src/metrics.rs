//! A small, dependency-free Prometheus metrics registry.
//!
//! Families are fixed at compile time (see [`Metrics`]); label values are
//! dynamic. Rendering is deterministic (families in declaration order, series
//! sorted by label values), which keeps the text format diff-able in tests.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// A labelled counter family.
#[derive(Debug)]
pub struct CounterVec {
    name: &'static str,
    help: &'static str,
    labels: &'static [&'static str],
    series: Mutex<BTreeMap<Vec<String>, u64>>,
}

impl CounterVec {
    const fn new(name: &'static str, help: &'static str, labels: &'static [&'static str]) -> Self {
        CounterVec {
            name,
            help,
            labels,
            series: Mutex::new(BTreeMap::new()),
        }
    }

    /// Add `n` to the series identified by `values` (one per label).
    pub fn add(&self, values: &[&str], n: u64) {
        debug_assert_eq!(values.len(), self.labels.len(), "{}", self.name);
        let key: Vec<String> = values.iter().map(|v| v.to_string()).collect();
        let mut s = self.series.lock().unwrap_or_else(|p| p.into_inner());
        *s.entry(key).or_insert(0) += n;
    }

    /// Increment by one.
    pub fn inc(&self, values: &[&str]) {
        self.add(values, 1);
    }

    /// Current value of one series (0 if never touched).
    pub fn get(&self, values: &[&str]) -> u64 {
        let key: Vec<String> = values.iter().map(|v| v.to_string()).collect();
        let s = self.series.lock().unwrap_or_else(|p| p.into_inner());
        s.get(&key).copied().unwrap_or(0)
    }

    /// Sum over all series.
    pub fn total(&self) -> u64 {
        let s = self.series.lock().unwrap_or_else(|p| p.into_inner());
        s.values().sum()
    }

    fn render(&self, out: &mut String) {
        let _ = writeln!(out, "# HELP {} {}", self.name, self.help);
        let _ = writeln!(out, "# TYPE {} counter", self.name);
        let s = self.series.lock().unwrap_or_else(|p| p.into_inner());
        for (values, v) in s.iter() {
            let _ = writeln!(
                out,
                "{}{} {v}",
                self.name,
                label_set(self.labels, values, None)
            );
        }
    }
}

/// A labelled histogram family with fixed bucket bounds.
#[derive(Debug)]
pub struct HistogramVec {
    name: &'static str,
    help: &'static str,
    labels: &'static [&'static str],
    bounds: &'static [f64],
    series: Mutex<BTreeMap<Vec<String>, HistogramData>>,
}

#[derive(Debug, Clone, Default)]
struct HistogramData {
    /// Non-cumulative per-bucket counts; the last slot is `+Inf`.
    buckets: Vec<u64>,
    sum: f64,
    count: u64,
}

impl HistogramVec {
    const fn new(
        name: &'static str,
        help: &'static str,
        labels: &'static [&'static str],
        bounds: &'static [f64],
    ) -> Self {
        HistogramVec {
            name,
            help,
            labels,
            bounds,
            series: Mutex::new(BTreeMap::new()),
        }
    }

    /// Record one observation.
    pub fn observe(&self, values: &[&str], v: f64) {
        debug_assert_eq!(values.len(), self.labels.len(), "{}", self.name);
        let key: Vec<String> = values.iter().map(|v| v.to_string()).collect();
        let mut s = self.series.lock().unwrap_or_else(|p| p.into_inner());
        let h = s.entry(key).or_insert_with(|| HistogramData {
            buckets: vec![0; self.bounds.len() + 1],
            ..HistogramData::default()
        });
        let idx = self
            .bounds
            .iter()
            .position(|b| v <= *b)
            .unwrap_or(self.bounds.len());
        h.buckets[idx] += 1;
        h.sum += v;
        h.count += 1;
    }

    /// Observation count of one series.
    pub fn count(&self, values: &[&str]) -> u64 {
        let key: Vec<String> = values.iter().map(|v| v.to_string()).collect();
        let s = self.series.lock().unwrap_or_else(|p| p.into_inner());
        s.get(&key).map(|h| h.count).unwrap_or(0)
    }

    fn render(&self, out: &mut String) {
        let _ = writeln!(out, "# HELP {} {}", self.name, self.help);
        let _ = writeln!(out, "# TYPE {} histogram", self.name);
        let s = self.series.lock().unwrap_or_else(|p| p.into_inner());
        for (values, h) in s.iter() {
            let mut cumulative = 0;
            for (i, c) in h.buckets.iter().enumerate() {
                cumulative += c;
                let le = self
                    .bounds
                    .get(i)
                    .map(|b| format_float(*b))
                    .unwrap_or_else(|| "+Inf".to_string());
                let _ = writeln!(
                    out,
                    "{}_bucket{} {cumulative}",
                    self.name,
                    label_set(self.labels, values, Some(&le))
                );
            }
            let labels = label_set(self.labels, values, None);
            let _ = writeln!(out, "{}_sum{labels} {}", self.name, format_float(h.sum));
            let _ = writeln!(out, "{}_count{labels} {}", self.name, h.count);
        }
    }
}

/// An unlabelled gauge.
#[derive(Debug)]
pub struct Gauge {
    name: &'static str,
    help: &'static str,
    value: AtomicI64,
}

impl Gauge {
    const fn new(name: &'static str, help: &'static str) -> Self {
        Gauge {
            name,
            help,
            value: AtomicI64::new(0),
        }
    }

    pub fn add(&self, d: i64) {
        self.value.fetch_add(d, Ordering::Relaxed);
    }

    pub fn set(&self, v: i64) {
        self.value.store(v, Ordering::Relaxed);
    }

    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }

    fn render(&self, out: &mut String) {
        let _ = writeln!(out, "# HELP {} {}", self.name, self.help);
        let _ = writeln!(out, "# TYPE {} gauge", self.name);
        let _ = writeln!(out, "{} {}", self.name, self.get());
    }
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn label_set(names: &[&str], values: &[String], le: Option<&str>) -> String {
    let mut parts: Vec<String> = names
        .iter()
        .zip(values)
        .map(|(n, v)| format!("{n}=\"{}\"", escape(v)))
        .collect();
    if let Some(le) = le {
        parts.push(format!("le=\"{le}\""));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("{{{}}}", parts.join(","))
    }
}

fn format_float(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{v:.1}")
    } else {
        format!("{v}")
    }
}

const LATENCY_BUCKETS: &[f64] = &[
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
];
const FUEL_BUCKETS: &[f64] = &[1e4, 1e5, 1e6, 1e7, 1e8, 1e9];

/// Every metric plugbox exports.
#[derive(Debug)]
pub struct Metrics {
    pub requests: CounterVec,
    pub request_duration: HistogramVec,
    pub instantiate_duration: HistogramVec,
    pub fuel_consumed: HistogramVec,
    pub traps: CounterVec,
    pub capability_denials: CounterVec,
    pub outbound_requests: CounterVec,
    pub guest_logs_dropped: CounterVec,
    pub shed: CounterVec,
    pub reloads: CounterVec,
    pub in_flight: Gauge,
    pub plugins_loaded: Gauge,
    pub generation: Gauge,
    started: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics::new()
    }
}

impl Metrics {
    /// A fresh registry.
    pub fn new() -> Metrics {
        Metrics {
            requests: CounterVec::new(
                "plugbox_requests_total",
                "Requests handled, by plugin and HTTP status.",
                &["plugin", "status"],
            ),
            request_duration: HistogramVec::new(
                "plugbox_request_duration_seconds",
                "Wall-clock time inside the sandbox (instantiate + handle).",
                &["plugin"],
                LATENCY_BUCKETS,
            ),
            instantiate_duration: HistogramVec::new(
                "plugbox_instantiate_duration_seconds",
                "Time to create a fresh instance from the pre-instantiated component.",
                &["plugin"],
                LATENCY_BUCKETS,
            ),
            fuel_consumed: HistogramVec::new(
                "plugbox_fuel_consumed",
                "Fuel consumed per request (fuel-metered plugins only).",
                &["plugin"],
                FUEL_BUCKETS,
            ),
            traps: CounterVec::new(
                "plugbox_traps_total",
                "Requests that ended in a trap, by cause.",
                &["plugin", "kind"],
            ),
            capability_denials: CounterVec::new(
                "plugbox_capability_denials_total",
                "Host calls refused because the capability was not granted or a policy refused it.",
                &["plugin", "capability"],
            ),
            outbound_requests: CounterVec::new(
                "plugbox_outbound_requests_total",
                "Outbound HTTP calls made by plugins, by result.",
                &["plugin", "result"],
            ),
            guest_logs_dropped: CounterVec::new(
                "plugbox_guest_log_lines_dropped_total",
                "Guest log lines dropped by the per-request cap.",
                &["plugin"],
            ),
            shed: CounterVec::new(
                "plugbox_shed_total",
                "Requests rejected with 503 because of load or an exhausted instance pool.",
                &["reason"],
            ),
            reloads: CounterVec::new(
                "plugbox_reloads_total",
                "Configuration reloads, by result.",
                &["result"],
            ),
            in_flight: Gauge::new(
                "plugbox_in_flight",
                "Plugin invocations currently executing.",
            ),
            plugins_loaded: Gauge::new("plugbox_plugins_loaded", "Plugins in the active snapshot."),
            generation: Gauge::new(
                "plugbox_config_generation",
                "Generation number of the active plugin snapshot.",
            ),
            started: AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            ),
        }
    }

    /// Render the Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.requests.render(&mut out);
        self.request_duration.render(&mut out);
        self.instantiate_duration.render(&mut out);
        self.fuel_consumed.render(&mut out);
        self.traps.render(&mut out);
        self.capability_denials.render(&mut out);
        self.outbound_requests.render(&mut out);
        self.guest_logs_dropped.render(&mut out);
        self.shed.render(&mut out);
        self.reloads.render(&mut out);
        self.in_flight.render(&mut out);
        self.plugins_loaded.render(&mut out);
        self.generation.render(&mut out);
        let _ = writeln!(
            out,
            "# HELP plugbox_start_time_seconds Unix time the process started.\n\
             # TYPE plugbox_start_time_seconds gauge\nplugbox_start_time_seconds {}",
            self.started.load(Ordering::Relaxed)
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_render_sorted_and_escaped() {
        let m = Metrics::new();
        m.requests.inc(&["b", "200"]);
        m.requests.add(&["a", "500"], 3);
        m.requests.inc(&["b", "200"]);
        m.traps.inc(&["we\"ird\\name\n", "fuel"]);
        assert_eq!(m.requests.get(&["b", "200"]), 2);
        assert_eq!(m.requests.get(&["zzz", "200"]), 0);
        assert_eq!(m.requests.total(), 5);
        let text = m.render();
        let a = text
            .find("plugbox_requests_total{plugin=\"a\",status=\"500\"} 3")
            .unwrap();
        let b = text
            .find("plugbox_requests_total{plugin=\"b\",status=\"200\"} 2")
            .unwrap();
        assert!(a < b, "series must be sorted");
        assert!(text.contains(r#"plugin="we\"ird\\name\n""#), "{text}");
        assert!(text.contains("# TYPE plugbox_requests_total counter"));
        assert!(text.contains("plugbox_start_time_seconds "));
    }

    #[test]
    fn histograms_are_cumulative() {
        let m = Metrics::new();
        for v in [0.00005, 0.003, 0.003, 7.0] {
            m.request_duration.observe(&["p"], v);
        }
        assert_eq!(m.request_duration.count(&["p"]), 4);
        assert_eq!(m.request_duration.count(&["q"]), 0);
        let text = m.render();
        assert!(
            text.contains(r#"plugbox_request_duration_seconds_bucket{plugin="p",le="0.0001"} 1"#)
        );
        assert!(
            text.contains(r#"plugbox_request_duration_seconds_bucket{plugin="p",le="0.005"} 3"#)
        );
        assert!(text.contains(r#"plugbox_request_duration_seconds_bucket{plugin="p",le="1.0"} 3"#));
        assert!(
            text.contains(r#"plugbox_request_duration_seconds_bucket{plugin="p",le="+Inf"} 4"#)
        );
        assert!(text.contains(r#"plugbox_request_duration_seconds_count{plugin="p"} 4"#));
        assert!(text.contains(r#"plugbox_request_duration_seconds_sum{plugin="p"} 7.00605"#));
    }

    #[test]
    fn gauges() {
        let m = Metrics::new();
        m.in_flight.add(2);
        m.in_flight.add(-1);
        m.generation.set(7);
        assert_eq!(m.in_flight.get(), 1);
        let text = m.render();
        assert!(text.contains("plugbox_in_flight 1\n"));
        assert!(text.contains("plugbox_config_generation 7\n"));
        assert_eq!(format_float(1e20), "100000000000000000000");
    }
}
