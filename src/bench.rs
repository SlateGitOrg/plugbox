//! Cold-start vs pooled-instance benchmark.
//!
//! Every mode measures the *full* per-request path the data plane runs
//! (store creation, limits, instantiation, `handle` call, teardown) against
//! the same component and request; they differ only in what is already
//! prepared when the request arrives:
//!
//! | mode | per-request work |
//! |---|---|
//! | `cold-jit` | JIT-compile the component, policy check, link, instantiate, call |
//! | `cold-aot` | deserialize an ahead-of-time artifact, link, instantiate, call |
//! | `warm-ondemand` | instantiate a pre-linked component with fresh `mmap`s, call |
//! | `warm-pooled` | instantiate into a pooling-allocator slot (CoW memory), call |
//!
//! Latency is measured single-threaded; throughput with `threads` workers.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::config::{Config, InstanceStrategy};
use crate::engine::EngineSettings;
use crate::error::{Error, Result};
use crate::host::Request;
use crate::runtime::{LoadedPlugin, Outcome, Runtime, RuntimeOptions};

/// Benchmark modes, in report order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    ColdJit,
    ColdAot,
    WarmOnDemand,
    WarmPooled,
}

impl Mode {
    pub const ALL: [Mode; 4] = [Mode::ColdJit, Mode::ColdAot, Mode::WarmOnDemand, Mode::WarmPooled];

    pub fn label(self) -> &'static str {
        match self {
            Mode::ColdJit => "cold-jit",
            Mode::ColdAot => "cold-aot",
            Mode::WarmOnDemand => "warm-ondemand",
            Mode::WarmPooled => "warm-pooled",
        }
    }

    fn is_cold(self) -> bool {
        matches!(self, Mode::ColdJit | Mode::ColdAot)
    }
}

/// Benchmark parameters.
#[derive(Clone, Debug)]
pub struct BenchOptions {
    pub component: PathBuf,
    /// Requests per warm mode (cold modes run `iterations / cold_divisor`).
    pub iterations: usize,
    pub cold_divisor: usize,
    pub threads: usize,
    /// Scratch directory for the AOT artifact.
    pub scratch: PathBuf,
    pub path: String,
}

/// Results for one mode.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ModeResult {
    pub mode: &'static str,
    pub samples: usize,
    pub p50_us: f64,
    pub p90_us: f64,
    pub p99_us: f64,
    pub mean_us: f64,
    pub max_us: f64,
    /// Instantiation share of the warm path (µs, p50); 0 for cold modes.
    pub instantiate_p50_us: f64,
    pub throughput_threads: usize,
    pub throughput_rps: f64,
}

/// `q`-quantile (nearest-rank) of sorted samples.
pub fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn plugin_config(component: &Path) -> Result<Config> {
    let text = format!(
        "[[plugins]]\nname = \"bench\"\nroute = \"/\"\ncomponent = {:?}\n\
         [plugins.limits]\nfuel = 0\ntimeout_ms = 10000\n\
         [plugins.grants.env]\nvars = {{ GREETING = \"bench\" }}\n",
        component.display().to_string()
    );
    Config::parse(&text, Path::new("."))
}

struct Fixture {
    runtime: Runtime,
    plugin: LoadedPlugin,
    bytes: Arc<Vec<u8>>,
    cfg: Config,
}

fn fixture(mode: Mode, opts: &BenchOptions, pool: u32) -> Result<Fixture> {
    let strategy = if mode == Mode::WarmPooled {
        InstanceStrategy::Pooling
    } else {
        InstanceStrategy::OnDemand
    };
    let cache_dir = (mode == Mode::ColdAot).then(|| opts.scratch.join("aot-cache"));
    let runtime = Runtime::new(RuntimeOptions {
        engine: EngineSettings {
            strategy,
            pool_size: pool,
            ..EngineSettings::default()
        },
        cache_dir,
        ..RuntimeOptions::default()
    })?;
    let bytes = std::fs::read(&opts.component).map_err(|source| Error::ComponentIo {
        path: opts.component.clone(),
        source,
    })?;
    let cfg = plugin_config(&opts.component)?;
    // For cold-aot this first compile also writes the artifact.
    let compiled = runtime.compile("bench", &bytes)?;
    let plugin = runtime.bind(&cfg.plugins[0], opts.component.clone(), compiled, 1)?;
    Ok(Fixture {
        runtime,
        plugin,
        bytes: Arc::new(bytes),
        cfg,
    })
}

fn one_request(f: &Fixture, mode: Mode, req: &Request) -> Result<Duration> {
    let started = Instant::now();
    let plugin = if mode.is_cold() {
        let compiled = f.runtime.compile("bench", &f.bytes)?;
        if mode == Mode::ColdAot && !compiled.from_cache {
            return Err(Error::Engine("AOT cache miss during cold-aot run".into()));
        }
        f.runtime
            .bind(&f.cfg.plugins[0], f.plugin.component_path.clone(), compiled, 1)?
    } else {
        f.plugin.clone()
    };
    let inv = f.runtime.invoke(&plugin, req);
    let elapsed = started.elapsed();
    match inv.outcome {
        Outcome::Response(r) if r.status == 200 => Ok(elapsed),
        other => Err(Error::Engine(format!("benchmark request failed: {other:?}"))),
    }
}

fn request(path: &str) -> Request {
    Request {
        method: "GET".into(),
        path: path.into(),
        query: "name=bench".into(),
        headers: vec![],
        body: vec![],
    }
}

/// Run one mode.
pub fn run_mode(mode: Mode, opts: &BenchOptions) -> Result<ModeResult> {
    let threads = opts.threads.max(1);
    let f = Arc::new(fixture(mode, opts, (threads as u32 * 2).max(8))?);
    let req = request(&opts.path);
    let n = if mode.is_cold() {
        (opts.iterations / opts.cold_divisor.max(1)).max(5)
    } else {
        opts.iterations.max(5)
    };
    // Warm-up (not recorded).
    for _ in 0..3 {
        one_request(&f, mode, &req)?;
    }
    let mut lat = Vec::with_capacity(n);
    let mut inst = Vec::with_capacity(n);
    for _ in 0..n {
        lat.push(one_request(&f, mode, &req)?.as_secs_f64() * 1e6);
        if !mode.is_cold() {
            let inv = f.runtime.invoke(&f.plugin, &req);
            inst.push(inv.stats.instantiate.as_secs_f64() * 1e6);
        }
    }
    lat.sort_by(f64::total_cmp);
    inst.sort_by(f64::total_cmp);

    let counter = Arc::new(AtomicUsize::new(0));
    let failures = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..threads {
            let f = f.clone();
            let counter = counter.clone();
            let failures = failures.clone();
            let req = req.clone();
            s.spawn(move || {
                while counter.fetch_add(1, Ordering::Relaxed) < n {
                    if one_request(&f, mode, &req).is_err() {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    let wall = started.elapsed().as_secs_f64();
    if failures.load(Ordering::Relaxed) > 0 {
        return Err(Error::Engine(format!(
            "{} requests failed during the throughput run",
            failures.load(Ordering::Relaxed)
        )));
    }
    Ok(ModeResult {
        mode: mode.label(),
        samples: n,
        p50_us: quantile(&lat, 0.50),
        p90_us: quantile(&lat, 0.90),
        p99_us: quantile(&lat, 0.99),
        mean_us: lat.iter().sum::<f64>() / lat.len() as f64,
        max_us: lat.last().copied().unwrap_or(0.0),
        instantiate_p50_us: quantile(&inst, 0.50),
        throughput_threads: threads,
        throughput_rps: n as f64 / wall,
    })
}

/// Run every mode.
pub fn run(opts: &BenchOptions) -> Result<Vec<ModeResult>> {
    std::fs::create_dir_all(&opts.scratch)?;
    let results = Mode::ALL
        .iter()
        .map(|m| run_mode(*m, opts))
        .collect::<Result<Vec<_>>>();
    let _ = std::fs::remove_dir_all(opts.scratch.join("aot-cache"));
    results
}

/// Markdown table of results.
pub fn render_table(results: &[ModeResult]) -> String {
    let mut out = String::from(
        "| mode | samples | p50 µs | p90 µs | p99 µs | mean µs | instantiate p50 µs | throughput (req/s) |\n\
         |---|---:|---:|---:|---:|---:|---:|---:|\n",
    );
    for r in results {
        out.push_str(&format!(
            "| {} | {} | {:.1} | {:.1} | {:.1} | {:.1} | {} | {:.0} ({} threads) |\n",
            r.mode,
            r.samples,
            r.p50_us,
            r.p90_us,
            r.p99_us,
            r.mean_us,
            if r.instantiate_p50_us > 0.0 {
                format!("{:.1}", r.instantiate_p50_us)
            } else {
                "—".to_string()
            },
            r.throughput_rps,
            r.throughput_threads
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_use_nearest_rank() {
        let v: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(quantile(&v, 0.5), 50.0);
        assert_eq!(quantile(&v, 0.99), 99.0);
        assert_eq!(quantile(&v, 1.0), 100.0);
        assert_eq!(quantile(&v, 0.0), 1.0);
        assert_eq!(quantile(&[], 0.5), 0.0);
    }

    #[test]
    fn table_rendering() {
        let r = ModeResult {
            mode: "warm-pooled",
            samples: 10,
            p50_us: 12.34,
            p90_us: 20.0,
            p99_us: 30.0,
            mean_us: 15.0,
            max_us: 31.0,
            instantiate_p50_us: 4.0,
            throughput_threads: 4,
            throughput_rps: 12345.6,
        };
        let cold = ModeResult {
            mode: "cold-jit",
            instantiate_p50_us: 0.0,
            ..r.clone()
        };
        let t = render_table(&[r, cold]);
        assert!(t.contains("| warm-pooled | 10 | 12.3 | 20.0 | 30.0 | 15.0 | 4.0 | 12346 (4 threads) |"));
        assert!(t.contains("| cold-jit | 10 | 12.3 | 20.0 | 30.0 | 15.0 | — |"));
        assert_eq!(Mode::ALL.map(Mode::label), ["cold-jit", "cold-aot", "warm-ondemand", "warm-pooled"]);
    }
}
