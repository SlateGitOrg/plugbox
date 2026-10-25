//! The sandbox runtime: compiling components, binding them to capability
//! grants, and executing one request in a fresh, limited instance.
//!
//! # Request lifecycle
//!
//! ```text
//! Store::new(HostState)            per-request state, locked-down WASI
//!   ├─ limiter(MemoryLimiter)      memory budget across all memories
//!   ├─ set_fuel(limits.fuel)       deterministic CPU budget
//!   └─ set_epoch_deadline(ticks)   wall-clock budget
//! PluginPre::instantiate           imports pre-resolved; pooled slot
//! handler.call_handle(request)     guest code runs
//! drop(Store)                      instance + memory returned to the pool
//! ```
//!
//! A guest instance never serves two requests: state cannot leak between
//! requests (or tenants) through linear memory, and a trapped instance —
//! which is unsafe to re-enter — is simply discarded.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use sha2::{Digest, Sha256};
use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, PoolConcurrencyLimitError, Store, Trap};

use crate::capability::Capabilities;
use crate::capability::kv::KvStore;
use crate::config::{Limits, PluginConfig, normalize_route};
use crate::engine::{EngineSettings, EpochTicker, build_engine, deadline_ticks};
use crate::error::{Error, Result};
use crate::host::{self, HostContext, HostState, PluginPre, Request, Response};
use crate::metrics::Metrics;
use crate::outbound::Outbound;
use crate::policy::{self, ImportReport};

/// Options for building a [`Runtime`].
#[derive(Clone, Debug, Default)]
pub struct RuntimeOptions {
    pub engine: EngineSettings,
    /// Directory for ahead-of-time compiled artifacts (trusted; see the
    /// threat model).
    pub cache_dir: Option<PathBuf>,
    pub outbound: Outbound,
    /// Largest response body a plugin may return.
    pub max_response_body: usize,
}

/// A component that passed the import policy and is linked against the
/// host, ready to be instantiated any number of times.
pub struct CompiledComponent {
    pre: PluginPre<HostState>,
    /// Hex SHA-256 of the component bytes.
    pub sha256: String,
    pub size: usize,
    pub report: ImportReport,
    pub compile_time: Duration,
    pub from_cache: bool,
}

impl std::fmt::Debug for CompiledComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledComponent")
            .field("sha256", &self.sha256)
            .field("size", &self.size)
            .field("from_cache", &self.from_cache)
            .finish_non_exhaustive()
    }
}

/// A compiled component bound to one plugin's route, limits and grants.
#[derive(Debug, Clone)]
pub struct LoadedPlugin {
    pub name: Arc<str>,
    /// Normalised mount route.
    pub route: String,
    pub component_path: PathBuf,
    pub limits: Limits,
    pub caps: Arc<Capabilities>,
    pub compiled: Arc<CompiledComponent>,
    /// Snapshot generation that loaded this version.
    pub generation: u64,
    pub loaded_at: SystemTime,
}

impl LoadedPlugin {
    /// First 12 hex chars of the component hash, used as a version tag.
    pub fn version(&self) -> &str {
        &self.compiled.sha256[..12]
    }
}

/// Why a request did not produce a plugin response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrapKind {
    /// The fuel budget ran out.
    FuelExhausted,
    /// The wall-clock (epoch) deadline passed.
    DeadlineExceeded,
    /// A memory growth was refused by the limiter.
    MemoryLimit,
    /// The engine's native wasm stack (`max_wasm_stack`) was exhausted.
    StackOverflow,
    /// Out-of-bounds linear-memory access — in Rust guests typically a
    /// shadow-stack overflow, since that stack lives in linear memory.
    MemoryFault,
    /// The guest aborted (`unreachable`, usually a Rust panic).
    GuestAbort,
    /// Any other trap or host error.
    Other,
}

impl TrapKind {
    /// Stable label used in metrics and the `x-plugbox-error` header.
    pub fn label(self) -> &'static str {
        match self {
            TrapKind::FuelExhausted => "fuel-exhausted",
            TrapKind::DeadlineExceeded => "deadline-exceeded",
            TrapKind::MemoryLimit => "memory-limit",
            TrapKind::StackOverflow => "stack-overflow",
            TrapKind::MemoryFault => "memory-fault",
            TrapKind::GuestAbort => "guest-abort",
            TrapKind::Other => "trap",
        }
    }
}

/// The result of one invocation.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// The plugin returned a valid response.
    Response(Response),
    /// The guest trapped; the instance was discarded.
    Trap { kind: TrapKind, detail: String },
    /// No instance slot was available.
    Overloaded(String),
    /// The plugin returned something the host refuses to forward.
    InvalidResponse(String),
}

impl Outcome {
    /// HTTP status the data plane answers with.
    pub fn http_status(&self) -> u16 {
        match self {
            Outcome::Response(r) => r.status,
            Outcome::Trap {
                kind: TrapKind::FuelExhausted | TrapKind::DeadlineExceeded,
                ..
            } => 504,
            Outcome::Trap { .. } | Outcome::InvalidResponse(_) => 502,
            Outcome::Overloaded(_) => 503,
        }
    }

    /// Value of the `x-plugbox-error` header (none for normal responses).
    pub fn error_label(&self) -> Option<&'static str> {
        match self {
            Outcome::Response(_) => None,
            Outcome::Trap { kind, .. } => Some(kind.label()),
            Outcome::Overloaded(_) => Some("overloaded"),
            Outcome::InvalidResponse(_) => Some("invalid-response"),
        }
    }
}

/// Measurements from one invocation.
#[derive(Debug, Clone, Default)]
pub struct InvocationStats {
    pub instantiate: Duration,
    pub total: Duration,
    pub fuel_consumed: u64,
    pub memory_peak: usize,
    pub outbound_calls: u32,
    pub log_lines: u32,
    pub denials: u32,
    /// Captured guest stdout+stderr (capped).
    pub stdio: String,
    pub stdio_dropped: usize,
}

/// Outcome plus stats.
#[derive(Debug, Clone)]
pub struct Invocation {
    pub outcome: Outcome,
    pub stats: InvocationStats,
}

/// The shared sandbox runtime.
pub struct Runtime {
    engine: Engine,
    linker: Linker<HostState>,
    kv: Arc<KvStore>,
    outbound: Outbound,
    metrics: Arc<Metrics>,
    settings: EngineSettings,
    cache_dir: Option<PathBuf>,
    max_response_body: usize,
    _ticker: EpochTicker,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn valid_header_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

impl Runtime {
    /// Build the engine, linker and epoch ticker.
    pub fn new(opts: RuntimeOptions) -> Result<Runtime> {
        let engine = build_engine(&opts.engine)?;
        let mut linker = Linker::new(&engine);
        host::add_to_linker(&mut linker).map_err(|e| Error::Engine(format!("{e:#}")))?;
        if let Some(dir) = &opts.cache_dir {
            std::fs::create_dir_all(dir)?;
        }
        let ticker = EpochTicker::start(engine.clone(), opts.engine.epoch_tick);
        Ok(Runtime {
            engine,
            linker,
            kv: Arc::new(KvStore::new()),
            outbound: opts.outbound,
            metrics: Arc::new(Metrics::new()),
            settings: opts.engine,
            cache_dir: opts.cache_dir,
            max_response_body: if opts.max_response_body == 0 {
                1 << 20
            } else {
                opts.max_response_body
            },
            _ticker: ticker,
        })
    }

    /// The shared metrics registry.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// The shared KV store.
    pub fn kv(&self) -> &Arc<KvStore> {
        &self.kv
    }

    /// The wasmtime engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Engine settings in effect.
    pub fn settings(&self) -> &EngineSettings {
        &self.settings
    }

    /// Live component instances in the pool (pooling strategy only).
    pub fn pool_live_instances(&self) -> Option<u64> {
        self.engine
            .pooling_allocator_metrics()
            .map(|m| m.component_instances())
    }

    fn cache_path(&self, sha: &str) -> Option<PathBuf> {
        use std::hash::{Hash, Hasher};
        let dir = self.cache_dir.as_ref()?;
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.engine.precompile_compatibility_hash().hash(&mut h);
        Some(dir.join(format!("{}-{:016x}.cwasm", &sha[..32], h.finish())))
    }

    fn load_component(&self, name: &str, bytes: &[u8], sha: &str) -> Result<(Component, bool)> {
        let cached = self.cache_path(sha);
        if let Some(path) = cached.as_ref().filter(|p| p.exists()) {
            // SAFETY: the cache directory is trusted and written only by
            // plugbox (see docs/THREAT_MODEL.md, "AOT cache"); files are keyed
            // by the component hash and the engine's compatibility hash, and
            // wasmtime still validates the artifact header against the engine.
            // The returned component keeps the file memory-mapped for its
            // whole lifetime, so entries are only ever replaced by rename
            // (`write_atomic`), never rewritten in place.
            match unsafe { Component::deserialize_file(&self.engine, path) } {
                Ok(c) => return Ok((c, true)),
                Err(e) => tracing::warn!(plugin = name, error = %e, "discarding bad cache entry"),
            }
        }
        let component =
            Component::new(&self.engine, bytes).map_err(|e| Error::component(name, &e))?;
        if let Some(path) = cached {
            match component.serialize() {
                Ok(artifact) => {
                    if let Err(e) = write_atomic(&path, &artifact) {
                        tracing::warn!(plugin = name, error = %e, "cannot write cache entry");
                    }
                }
                Err(e) => tracing::warn!(plugin = name, error = %e, "cannot serialize component"),
            }
        }
        Ok((component, false))
    }

    /// Compile (or load from the AOT cache), apply the import policy, and
    /// pre-link a component.
    pub fn compile(&self, name: &str, bytes: &[u8]) -> Result<Arc<CompiledComponent>> {
        let started = Instant::now();
        let sha = sha256_hex(bytes);
        let (component, from_cache) = self.load_component(name, bytes, &sha)?;
        let report = policy::inspect(&self.engine, &component);
        if !report.is_allowed() {
            return Err(Error::Policy {
                plugin: name.to_string(),
                violations: report.violations,
            });
        }
        let instance_pre = self
            .linker
            .instantiate_pre(&component)
            .map_err(|e| Error::component(name, &e))?;
        let pre = PluginPre::new(instance_pre).map_err(|e| Error::component(name, &e))?;
        Ok(Arc::new(CompiledComponent {
            pre,
            sha256: sha,
            size: bytes.len(),
            report,
            compile_time: started.elapsed(),
            from_cache,
        }))
    }

    /// Read and compile a component file.
    pub fn compile_file(&self, name: &str, path: &Path) -> Result<Arc<CompiledComponent>> {
        let bytes = std::fs::read(path).map_err(|source| Error::ComponentIo {
            path: path.to_path_buf(),
            source,
        })?;
        self.compile(name, &bytes)
    }

    /// Bind a compiled component to a plugin configuration.
    pub fn bind(
        &self,
        cfg: &PluginConfig,
        component_path: PathBuf,
        compiled: Arc<CompiledComponent>,
        generation: u64,
    ) -> Result<LoadedPlugin> {
        if cfg.limits.memory.as_usize() > self.settings.max_memory {
            return Err(Error::ConfigInvalid(format!(
                "plugin `{}`: limits.memory exceeds the engine's max_memory",
                cfg.name
            )));
        }
        let (caps, warnings) = Capabilities::resolve(cfg, |n| std::env::var(n).ok())
            .map_err(|e| Error::ConfigInvalid(format!("plugin `{}`: {e}", cfg.name)))?;
        for w in warnings {
            tracing::warn!(plugin = %cfg.name, "{w}");
        }
        Ok(LoadedPlugin {
            name: Arc::from(cfg.name.as_str()),
            route: normalize_route(&cfg.route).unwrap_or_else(|| cfg.route.clone()),
            component_path,
            limits: cfg.limits.clone(),
            caps: Arc::new(caps),
            compiled,
            generation,
            loaded_at: SystemTime::now(),
        })
    }

    /// Execute one request in a fresh instance. Never panics on guest
    /// misbehaviour; every failure is an [`Outcome`].
    pub fn invoke(&self, plugin: &LoadedPlugin, req: &Request) -> Invocation {
        let started = Instant::now();
        let limits = &plugin.limits;
        let deadline = started + limits.timeout();
        let state = HostState::new(HostContext {
            plugin: plugin.name.clone(),
            caps: plugin.caps.clone(),
            kv: self.kv.clone(),
            outbound: self.outbound.clone(),
            metrics: self.metrics.clone(),
            memory_limit: limits.memory.as_usize(),
            deadline,
            max_log_lines: limits.max_log_lines,
            max_stdio: limits.max_stdio.as_usize(),
        });
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limiter);
        let fuel_budget = if limits.fuel == 0 {
            u64::MAX
        } else {
            limits.fuel
        };
        // Fuel is enabled engine-wide, so this cannot fail.
        let _ = store.set_fuel(fuel_budget);
        store.set_epoch_deadline(deadline_ticks(limits.timeout(), self.settings.epoch_tick));

        self.metrics.in_flight.add(1);
        let mut instantiate = Duration::ZERO;
        let result = plugin
            .compiled
            .pre
            .instantiate(&mut store)
            .map_err(|e| (true, e))
            .and_then(|bindings| {
                instantiate = started.elapsed();
                bindings
                    .plugbox_host_handler()
                    .call_handle(&mut store, req)
                    .map_err(|e| (false, e))
            });
        self.metrics.in_flight.add(-1);

        let fuel_left = store.get_fuel().unwrap_or(0);
        let state = store.data();
        let mut stats = InvocationStats {
            instantiate,
            total: started.elapsed(),
            fuel_consumed: fuel_budget.saturating_sub(fuel_left),
            memory_peak: state.limiter.peak(),
            outbound_calls: state.outbound_calls(),
            log_lines: state.log_lines(),
            denials: state.denials,
            stdio: state.stdio.contents(),
            stdio_dropped: state.stdio.dropped(),
        };
        let outcome = match result {
            // A guest wait cut short by the deadline is a deadline trap even
            // if the epoch check did not fire before the guest returned.
            Ok(_) if state.sleep_cut() => Outcome::Trap {
                kind: TrapKind::DeadlineExceeded,
                detail: "guest blocked in wasi:io/poll past the request deadline".into(),
            },
            Ok(resp) => self.validate(resp),
            Err((during_instantiate, err)) => classify(&err, state, during_instantiate),
        };
        drop(store);
        stats.total = started.elapsed();
        self.record(plugin, &outcome, &stats);
        Invocation { outcome, stats }
    }

    fn validate(&self, resp: Response) -> Outcome {
        if !(200..=599).contains(&resp.status) {
            return Outcome::InvalidResponse(format!("status {} out of range", resp.status));
        }
        if resp.body.len() > self.max_response_body {
            return Outcome::InvalidResponse(format!(
                "body of {} bytes exceeds the {} byte limit",
                resp.body.len(),
                self.max_response_body
            ));
        }
        for (k, v) in &resp.headers {
            if !valid_header_name(k) || v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
                return Outcome::InvalidResponse(format!("invalid header `{k}`"));
            }
        }
        Outcome::Response(resp)
    }

    fn record(&self, plugin: &LoadedPlugin, outcome: &Outcome, stats: &InvocationStats) {
        let m = &self.metrics;
        let name = &*plugin.name;
        let status = outcome.http_status().to_string();
        m.requests.inc(&[name, &status]);
        m.request_duration
            .observe(&[name], stats.total.as_secs_f64());
        if !stats.instantiate.is_zero() {
            m.instantiate_duration
                .observe(&[name], stats.instantiate.as_secs_f64());
        }
        if plugin.limits.fuel != 0 {
            m.fuel_consumed.observe(&[name], stats.fuel_consumed as f64);
        }
        match outcome {
            Outcome::Trap { kind, detail } => {
                m.traps.inc(&[name, kind.label()]);
                tracing::warn!(plugin = name, kind = kind.label(), %detail, "plugin trapped");
            }
            Outcome::Overloaded(why) => {
                m.shed.inc(&["pool_exhausted"]);
                tracing::warn!(plugin = name, %why, "no instance slot");
            }
            Outcome::InvalidResponse(why) => {
                m.traps.inc(&[name, "invalid-response"]);
                tracing::warn!(plugin = name, %why, "invalid plugin response");
            }
            Outcome::Response(_) => {}
        }
        if !stats.stdio.is_empty() {
            tracing::debug!(plugin = name, stdio = %stats.stdio, dropped = stats.stdio_dropped, "guest output");
        }
    }
}

fn classify(err: &wasmtime::Error, state: &HostState, during_instantiate: bool) -> Outcome {
    if err.downcast_ref::<PoolConcurrencyLimitError>().is_some() {
        return Outcome::Overloaded(format!("{err}"));
    }
    // The top-level message is wasmtime's backtrace context; the trap (or
    // host error) that caused it is the useful part.
    let detail = match err.downcast_ref::<Trap>() {
        Some(trap) => trap.to_string(),
        None => err.root_cause().to_string(),
    };
    if let Some(requested) = state.limiter.denied() {
        return Outcome::Trap {
            kind: TrapKind::MemoryLimit,
            detail: format!(
                "memory growth to {requested} bytes refused ({})",
                if during_instantiate {
                    "at instantiation"
                } else {
                    "while handling"
                }
            ),
        };
    }
    let kind = match err.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => TrapKind::FuelExhausted,
        Some(Trap::Interrupt) => TrapKind::DeadlineExceeded,
        Some(Trap::StackOverflow) => TrapKind::StackOverflow,
        Some(Trap::MemoryOutOfBounds) => TrapKind::MemoryFault,
        Some(Trap::UnreachableCodeReached) => TrapKind::GuestAbort,
        _ => TrapKind::Other,
    };
    Outcome::Trap { kind, detail }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, headers: Vec<(&str, &str)>, body: usize) -> Response {
        Response {
            status,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: vec![b'x'; body],
        }
    }

    fn runtime() -> Runtime {
        Runtime::new(RuntimeOptions {
            engine: EngineSettings {
                pool_size: 2,
                ..EngineSettings::default()
            },
            max_response_body: 10,
            ..RuntimeOptions::default()
        })
        .unwrap()
    }

    #[test]
    fn response_validation() {
        let rt = runtime();
        assert!(matches!(
            rt.validate(resp(200, vec![("x-a", "b")], 10)),
            Outcome::Response(_)
        ));
        for bad in [
            resp(99, vec![], 0),
            resp(600, vec![], 0),
            resp(200, vec![], 11),
            resp(200, vec![("bad name", "v")], 0),
            resp(200, vec![("x", "a\r\nset-cookie: y")], 0),
        ] {
            assert!(matches!(rt.validate(bad), Outcome::InvalidResponse(_)));
        }
    }

    #[test]
    fn outcome_mapping() {
        let trap = |kind| Outcome::Trap {
            kind,
            detail: String::new(),
        };
        assert_eq!(trap(TrapKind::FuelExhausted).http_status(), 504);
        assert_eq!(trap(TrapKind::DeadlineExceeded).http_status(), 504);
        assert_eq!(trap(TrapKind::MemoryLimit).http_status(), 502);
        assert_eq!(Outcome::Overloaded(String::new()).http_status(), 503);
        assert_eq!(Outcome::InvalidResponse(String::new()).http_status(), 502);
        assert_eq!(Outcome::Response(resp(201, vec![], 0)).http_status(), 201);
        assert_eq!(Outcome::Response(resp(201, vec![], 0)).error_label(), None);
        assert_eq!(
            trap(TrapKind::StackOverflow).error_label(),
            Some("stack-overflow")
        );
        assert_eq!(
            trap(TrapKind::GuestAbort).error_label(),
            Some("guest-abort")
        );
        assert_eq!(
            trap(TrapKind::MemoryFault).error_label(),
            Some("memory-fault")
        );
        assert_eq!(trap(TrapKind::Other).error_label(), Some("trap"));
        assert_eq!(
            Outcome::Overloaded(String::new()).error_label(),
            Some("overloaded")
        );
    }

    #[test]
    fn rejects_non_components_and_policy_violations() {
        let rt = runtime();
        assert!(matches!(
            rt.compile("x", b"not wasm"),
            Err(Error::Component { .. })
        ));
        let sockets = br#"(component (import "wasi:sockets/tcp@0.2.0" (instance)))"#;
        match rt.compile("x", sockets) {
            Err(Error::Policy { violations, .. }) => assert_eq!(violations.len(), 2),
            other => panic!("expected policy error, got {other:?}"),
        }
        let missing = rt
            .compile_file("x", Path::new("/no/such/file.wasm"))
            .unwrap_err();
        assert!(matches!(missing, Error::ComponentIo { .. }));
        assert_eq!(sha256_hex(b"abc").len(), 64);
        assert!(rt.pool_live_instances().is_some());
        assert!(format!("{rt:?}").contains("Runtime"));
    }
}
