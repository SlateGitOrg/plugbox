//! Route table snapshots and hot reload.
//!
//! The data plane reads an immutable [`Snapshot`] (`Arc` clone under a short
//! read lock); a reload builds a complete new snapshot off to the side and
//! swaps it in with one pointer write. Consequences:
//!
//! * In-flight requests finish on the version they started with — they hold
//!   an `Arc` to their `LoadedPlugin`.
//! * Reloads are all-or-nothing: if any plugin fails to read, compile, pass
//!   the import policy or link, the old snapshot stays active and the error
//!   is reported (admin endpoint, metrics, log).
//! * Components whose bytes did not change are not recompiled; only their
//!   grants/limits are re-bound.
//!
//! The [`Watcher`] polls the config file and every component file. A change
//! is acted on once the file's (mtime, size) has been stable for one poll
//! interval, so half-written files are not loaded.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use crate::config::{Config, RuntimeConfig, ServerConfig};
use crate::error::{Error, Result};
use crate::runtime::{CompiledComponent, LoadedPlugin, Runtime, sha256_hex};

/// (mtime, length) of every watched file; `None` if unreadable.
pub type Fingerprint = BTreeMap<PathBuf, Option<(SystemTime, u64)>>;

fn stamp(path: &Path) -> Option<(SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

fn fingerprint(paths: impl IntoIterator<Item = PathBuf>) -> Fingerprint {
    paths
        .into_iter()
        .map(|p| {
            let s = stamp(&p);
            (p, s)
        })
        .collect()
}

/// An immutable, routable set of plugins.
#[derive(Debug)]
pub struct Snapshot {
    pub generation: u64,
    /// Sorted by route length, longest first (longest-prefix match).
    plugins: Vec<Arc<LoadedPlugin>>,
    fingerprint: Fingerprint,
}

/// Does `route` cover `path`? Returns the path relative to the mount point.
fn strip_route<'a>(route: &str, path: &'a str) -> Option<&'a str> {
    if route == "/" {
        return Some(path);
    }
    let rest = path.strip_prefix(route)?;
    if rest.is_empty() {
        Some("/")
    } else if rest.starts_with('/') {
        Some(rest)
    } else {
        None
    }
}

impl Snapshot {
    fn new(generation: u64, mut plugins: Vec<Arc<LoadedPlugin>>, fingerprint: Fingerprint) -> Self {
        plugins.sort_by(|a, b| b.route.len().cmp(&a.route.len()).then(a.route.cmp(&b.route)));
        Snapshot {
            generation,
            plugins,
            fingerprint,
        }
    }

    /// Find the plugin serving `path` and the plugin-relative path.
    pub fn route(&self, path: &str) -> Option<(Arc<LoadedPlugin>, String)> {
        self.plugins.iter().find_map(|p| {
            strip_route(&p.route, path).map(|rest| (p.clone(), rest.to_string()))
        })
    }

    /// Every plugin, longest route first.
    pub fn plugins(&self) -> &[Arc<LoadedPlugin>] {
        &self.plugins
    }

    /// Look a plugin up by name.
    pub fn get(&self, name: &str) -> Option<Arc<LoadedPlugin>> {
        self.plugins.iter().find(|p| &*p.name == name).cloned()
    }
}

/// What a reload changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReloadReport {
    pub generation: u64,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// Component bytes changed (recompiled or loaded from cache).
    pub updated: Vec<String>,
    /// Same component, new limits/grants/route.
    pub rebound: Vec<String>,
    pub unchanged: Vec<String>,
    /// Non-fatal notes (e.g. settings that need a restart).
    pub warnings: Vec<String>,
}

impl ReloadReport {
    /// One-line summary for logs.
    pub fn summary(&self) -> String {
        format!(
            "generation {}: +{} -{} ~{} rebound {} unchanged {}",
            self.generation,
            self.added.len(),
            self.removed.len(),
            self.updated.len(),
            self.rebound.len(),
            self.unchanged.len()
        )
    }
}

/// Owner of the active snapshot.
pub struct Registry {
    runtime: Arc<Runtime>,
    config_path: PathBuf,
    current: RwLock<Arc<Snapshot>>,
    reload_lock: Mutex<()>,
    last_error: Mutex<Option<String>>,
    boot_server: ServerConfig,
    boot_runtime: RuntimeConfig,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("config_path", &self.config_path)
            .field("generation", &self.snapshot().generation)
            .finish_non_exhaustive()
    }
}

impl Registry {
    /// Load the initial snapshot; any error is fatal.
    pub fn load(runtime: Arc<Runtime>, config_path: &Path) -> Result<Registry> {
        let config = Config::load(config_path)?;
        let (snapshot, _) = build(&runtime, config_path, &config, None, 1)?;
        runtime.metrics().generation.set(1);
        runtime
            .metrics()
            .plugins_loaded
            .set(snapshot.plugins.len() as i64);
        Ok(Registry {
            runtime,
            config_path: config_path.to_path_buf(),
            current: RwLock::new(Arc::new(snapshot)),
            reload_lock: Mutex::new(()),
            last_error: Mutex::new(None),
            boot_server: config.server,
            boot_runtime: config.runtime,
        })
    }

    /// The runtime plugins execute on.
    pub fn runtime(&self) -> &Arc<Runtime> {
        &self.runtime
    }

    /// Path of the watched configuration file.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// The active snapshot.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.current
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Error from the most recent failed reload, cleared by a successful one.
    pub fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Re-read the config and components and atomically swap the snapshot.
    pub fn reload(&self) -> Result<ReloadReport> {
        let _serial = self.reload_lock.lock().unwrap_or_else(|p| p.into_inner());
        let metrics = self.runtime.metrics().clone();
        let result = Config::load(&self.config_path).and_then(|config| {
            let old = self.snapshot();
            let (snapshot, mut report) = build(
                &self.runtime,
                &self.config_path,
                &config,
                Some(&old),
                old.generation + 1,
            )?;
            if config.server != self.boot_server {
                report
                    .warnings
                    .push("[server] changed; restart plugbox to apply it".into());
            }
            if config.runtime != self.boot_runtime {
                report
                    .warnings
                    .push("[runtime] changed; restart plugbox to apply it".into());
            }
            Ok((snapshot, report))
        });
        let mut last = self.last_error.lock().unwrap_or_else(|p| p.into_inner());
        match result {
            Ok((snapshot, report)) => {
                metrics.generation.set(snapshot.generation as i64);
                metrics.plugins_loaded.set(snapshot.plugins.len() as i64);
                *self.current.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(snapshot);
                metrics.reloads.inc(&["ok"]);
                *last = None;
                for w in &report.warnings {
                    tracing::warn!("{w}");
                }
                tracing::info!("reloaded: {}", report.summary());
                Ok(report)
            }
            Err(e) => {
                metrics.reloads.inc(&["error"]);
                tracing::error!(error = %e, "reload failed; keeping the previous snapshot");
                *last = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// Start a polling watcher; it stops when the returned handle drops.
    pub fn watch(self: &Arc<Self>, poll: Duration) -> Watcher {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let registry = Arc::downgrade(self);
        let handle = std::thread::Builder::new()
            .name("plugbox-reload".into())
            .spawn(move || {
                let mut pending: Option<Fingerprint> = None;
                let mut failed: Option<Fingerprint> = None;
                while !flag.load(Ordering::Relaxed) {
                    std::thread::park_timeout(poll);
                    if flag.load(Ordering::Relaxed) {
                        break;
                    }
                    let Some(reg) = registry.upgrade() else { break };
                    let snap = reg.snapshot();
                    let now = fingerprint(snap.fingerprint.keys().cloned());
                    if now == snap.fingerprint || failed.as_ref() == Some(&now) {
                        pending = None;
                        continue;
                    }
                    if pending.as_ref() != Some(&now) {
                        // First sighting: wait one interval for writes to settle.
                        pending = Some(now);
                        continue;
                    }
                    pending = None;
                    failed = reg.reload().is_err().then_some(now);
                }
            })
            .expect("spawn reload watcher thread");
        Watcher {
            stop,
            handle: Some(handle),
        }
    }
}

/// Handle to the background watcher thread.
#[derive(Debug)]
pub struct Watcher {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            h.thread().unpark();
            let _ = h.join();
        }
    }
}

/// Build a snapshot from `config`, reusing compiled components from `old`
/// when the bytes are identical.
fn build(
    runtime: &Runtime,
    config_path: &Path,
    config: &Config,
    old: Option<&Snapshot>,
    generation: u64,
) -> Result<(Snapshot, ReloadReport)> {
    let mut report = ReloadReport {
        generation,
        ..ReloadReport::default()
    };
    let mut plugins = Vec::with_capacity(config.plugins.len());
    let mut watched = vec![config_path.to_path_buf()];
    // Components compiled during this build, so several plugins sharing one
    // component file compile it once.
    let mut fresh: BTreeMap<String, Arc<CompiledComponent>> = BTreeMap::new();
    for pc in &config.plugins {
        let path = config.resolve(&pc.component);
        let bytes = std::fs::read(&path).map_err(|source| Error::ComponentIo {
            path: path.clone(),
            source,
        })?;
        let sha = sha256_hex(&bytes);
        let previous = old.and_then(|o| o.get(&pc.name));
        let reusable: Option<Arc<CompiledComponent>> = fresh.get(&sha).cloned().or_else(|| {
            old.and_then(|o| {
                o.plugins
                    .iter()
                    .find(|p| p.compiled.sha256 == sha)
                    .map(|p| p.compiled.clone())
            })
        });
        let compiled = match reusable {
            Some(c) => c,
            None => runtime.compile(&pc.name, &bytes)?,
        };
        fresh.insert(sha, compiled.clone());
        let plugin = runtime.bind(pc, path.clone(), compiled, generation)?;
        match previous {
            None if old.is_some() => report.added.push(pc.name.clone()),
            None => {}
            Some(prev) if prev.compiled.sha256 != plugin.compiled.sha256 => {
                report.updated.push(pc.name.clone());
            }
            Some(prev)
                if prev.limits != plugin.limits
                    || prev.route != plugin.route
                    || format!("{:?}", prev.caps) != format!("{:?}", plugin.caps) =>
            {
                report.rebound.push(pc.name.clone());
            }
            Some(_) => report.unchanged.push(pc.name.clone()),
        }
        tracing::info!(
            plugin = %plugin.name,
            route = %plugin.route,
            version = plugin.version(),
            grants = %plugin.caps.summary(),
            "plugin ready"
        );
        watched.push(path);
        plugins.push(Arc::new(plugin));
    }
    if let Some(o) = old {
        let new_names: BTreeSet<&str> = config.plugins.iter().map(|p| p.name.as_str()).collect();
        report.removed = o
            .plugins
            .iter()
            .filter(|p| !new_names.contains(&*p.name))
            .map(|p| p.name.to_string())
            .collect();
        report.removed.sort();
    }
    Ok((Snapshot::new(generation, plugins, fingerprint(watched)), report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_stripping() {
        assert_eq!(strip_route("/", "/x/y"), Some("/x/y"));
        assert_eq!(strip_route("/api", "/api"), Some("/"));
        assert_eq!(strip_route("/api", "/api/v1"), Some("/v1"));
        assert_eq!(strip_route("/api", "/apiv1"), None);
        assert_eq!(strip_route("/api", "/other"), None);
    }

    #[test]
    fn fingerprints_track_changes() {
        let dir = std::env::temp_dir().join(format!("plugbox-fp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a");
        let missing = dir.join("missing");
        std::fs::write(&f, "1").unwrap();
        let a = fingerprint([f.clone(), missing.clone()]);
        assert!(a[&missing].is_none());
        std::fs::write(&f, "22").unwrap();
        let b = fingerprint([f.clone(), missing]);
        assert_ne!(a, b, "length change must be visible");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn report_summary() {
        let r = ReloadReport {
            generation: 3,
            added: vec!["a".into()],
            ..ReloadReport::default()
        };
        assert_eq!(r.summary(), "generation 3: +1 -0 ~0 rebound 0 unchanged 0");
    }
}
