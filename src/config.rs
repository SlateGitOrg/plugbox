//! `plugbox.toml` — the operator's configuration.
//!
//! The file has three parts:
//!
//! * `[server]` — listeners and data-plane limits (restart to change).
//! * `[runtime]` — engine, pooling and reload settings (restart to change).
//! * `[[plugins]]` — one table per plugin: mount route, component path,
//!   resource limits and capability grants. These are hot-reloadable.
//!
//! Every capability is deny-by-default: a plugin without a `grants.http`
//! table cannot make outbound calls, without `grants.kv` cannot touch the
//! key-value store, and sees only the env vars listed under `grants.env`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::allowlist::AllowRule;
use crate::error::{Error, Result};

/// A byte count that can be written as an integer (`1048576`) or a string
/// with a binary unit (`"1MiB"`, `"512KiB"`, `"2GiB"`, `"64B"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteSize(pub u64);

impl ByteSize {
    /// Parse the string form.
    pub fn parse(s: &str) -> Option<ByteSize> {
        let s = s.trim();
        let split = s
            .find(|c: char| !c.is_ascii_digit() && c != '_')
            .unwrap_or(s.len());
        let (digits, unit) = s.split_at(split);
        let n: u64 = digits.replace('_', "").parse().ok()?;
        let mul: u64 = match unit.trim() {
            "" | "B" => 1,
            "KiB" | "K" | "KB" => 1 << 10,
            "MiB" | "M" | "MB" => 1 << 20,
            "GiB" | "G" | "GB" => 1 << 30,
            _ => return None,
        };
        n.checked_mul(mul).map(ByteSize)
    }

    /// The value as `usize` (saturating on 32-bit targets).
    pub fn as_usize(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.0;
        if n >= 1 << 30 && n.is_multiple_of(1 << 30) {
            write!(f, "{}GiB", n >> 30)
        } else if n >= 1 << 20 && n.is_multiple_of(1 << 20) {
            write!(f, "{}MiB", n >> 20)
        } else if n >= 1 << 10 && n.is_multiple_of(1 << 10) {
            write!(f, "{}KiB", n >> 10)
        } else {
            write!(f, "{n}B")
        }
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Int(u64),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Int(n) => Ok(ByteSize(n)),
            Raw::Str(s) => ByteSize::parse(&s).ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "invalid byte size `{s}` (use e.g. 65536, \"64KiB\", \"32MiB\")"
                ))
            }),
        }
    }
}

/// The whole configuration file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
    /// Directory relative paths are resolved against (the config file's
    /// directory). Not part of the file format.
    #[serde(skip)]
    pub base_dir: PathBuf,
}

/// `[server]`: listeners and data-plane limits.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// Data-plane listener.
    pub listen: SocketAddr,
    /// Admin listener (health, metrics, plugin list, reload). Keep it on
    /// loopback or a private network.
    pub admin_listen: Option<SocketAddr>,
    /// Concurrent plugin invocations; requests beyond this are shed with 503.
    pub max_concurrency: usize,
    /// Largest accepted request body.
    pub max_request_body: ByteSize,
    /// Largest response body a plugin may return.
    pub max_response_body: ByteSize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            admin_listen: Some(SocketAddr::from(([127, 0, 0, 1], 9901))),
            max_concurrency: 64,
            max_request_body: ByteSize(1 << 20),
            max_response_body: ByteSize(1 << 20),
        }
    }
}

/// How guest instances are allocated.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum InstanceStrategy {
    /// Wasmtime's pooling allocator: pre-reserved slots, copy-on-write
    /// memory images, slot reuse with `madvise` resets.
    Pooling,
    /// mmap a fresh memory per instance.
    OnDemand,
}

/// `[runtime]`: engine-level settings.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct RuntimeConfig {
    pub instance_strategy: InstanceStrategy,
    /// Number of component instances the pool can hold at once.
    pub pool_size: u32,
    /// Upper bound for any single plugin's `limits.memory`; sizes pool slots.
    pub max_memory: ByteSize,
    /// Epoch tick period in milliseconds (wall-clock deadline granularity).
    pub epoch_tick_ms: u64,
    /// Ahead-of-time compilation cache directory (optional).
    pub cache_dir: Option<PathBuf>,
    /// How often to poll config and component files for changes; 0 disables
    /// hot reload by file watching (the admin endpoint still works).
    pub reload_poll_ms: u64,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        RuntimeConfig {
            instance_strategy: InstanceStrategy::Pooling,
            pool_size: 128,
            max_memory: ByteSize(64 << 20),
            epoch_tick_ms: 5,
            cache_dir: None,
            reload_poll_ms: 500,
        }
    }
}

/// One `[[plugins]]` entry.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    /// Unique name; used in metrics labels and as the default KV namespace.
    pub name: String,
    /// Mount point; requests under this prefix are routed to the plugin.
    pub route: String,
    /// Path to the `.wasm` component (relative to the config file).
    pub component: PathBuf,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub grants: Grants,
}

/// Per-plugin resource limits.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Fuel per request (roughly one unit per wasm instruction). 0 disables
    /// fuel accounting for this plugin, leaving only the wall-clock deadline.
    pub fuel: u64,
    /// Wall-clock budget per request, enforced by epoch interruption.
    pub timeout_ms: u64,
    /// Total linear memory per instance (all memories combined).
    pub memory: ByteSize,
    /// Maximum log lines per request; further lines are counted and dropped.
    pub max_log_lines: u32,
    /// Captured stdout+stderr per request; the rest is dropped.
    pub max_stdio: ByteSize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            fuel: 50_000_000,
            timeout_ms: 250,
            memory: ByteSize(32 << 20),
            max_log_lines: 100,
            max_stdio: ByteSize(16 << 10),
        }
    }
}

impl Limits {
    /// The wall-clock budget.
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

/// Capability grants. Absent table = capability denied.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Grants {
    #[serde(default)]
    pub env: EnvGrant,
    pub http: Option<HttpGrant>,
    pub kv: Option<KvGrant>,
}

/// `grants.env`: the only variables the plugin can see.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct EnvGrant {
    /// Literal values.
    pub vars: BTreeMap<String, String>,
    /// Names copied from the host process environment at load time (missing
    /// ones are skipped with a warning).
    pub inherit: BTreeSet<String>,
}

/// `grants.http`: outbound HTTP allow-list and budgets.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpGrant {
    /// Allow rules such as `http://127.0.0.1:9000/api/*` or
    /// `https://*.example.com`.
    pub allow: Vec<String>,
    /// Permit hostname rules to resolve to loopback/private addresses.
    /// Cloud-metadata (link-local) addresses are refused regardless.
    #[serde(default)]
    pub allow_private: bool,
    /// Outbound calls allowed per inbound request.
    #[serde(default = "default_http_max_requests")]
    pub max_requests: u32,
    /// Per-call timeout (further capped by the remaining request budget).
    #[serde(default = "default_http_timeout_ms")]
    pub timeout_ms: u64,
    /// Largest upstream response body accepted.
    #[serde(default = "default_http_max_response")]
    pub max_response: ByteSize,
}

fn default_http_max_requests() -> u32 {
    8
}
fn default_http_timeout_ms() -> u64 {
    2_000
}
fn default_http_max_response() -> ByteSize {
    ByteSize(1 << 20)
}

/// KV access mode.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KvMode {
    #[default]
    ReadWrite,
    ReadOnly,
}

/// `grants.kv`: namespace and quotas.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KvGrant {
    /// Namespace; defaults to the plugin name. Two plugins may share one
    /// namespace only if both name it explicitly.
    pub namespace: Option<String>,
    #[serde(default)]
    pub mode: KvMode,
    #[serde(default = "default_kv_max_keys")]
    pub max_keys: usize,
    #[serde(default = "default_kv_max_value")]
    pub max_value: ByteSize,
}

fn default_kv_max_keys() -> usize {
    10_000
}
fn default_kv_max_value() -> ByteSize {
    ByteSize(64 << 10)
}

impl Config {
    /// Read, parse and validate a configuration file.
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::ConfigIo {
            path: path.to_path_buf(),
            source,
        })?;
        let base = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        Config::parse(&text, &base).map_err(|e| match e {
            Error::ConfigParse { message, .. } => Error::ConfigParse {
                path: path.to_path_buf(),
                message,
            },
            other => other,
        })
    }

    /// Parse and validate configuration text; relative paths resolve
    /// against `base_dir`.
    pub fn parse(text: &str, base_dir: &Path) -> Result<Config> {
        let mut cfg: Config = toml::from_str(text).map_err(|e| Error::ConfigParse {
            path: PathBuf::from("<inline>"),
            message: e.message().to_string(),
        })?;
        cfg.base_dir = base_dir.to_path_buf();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Resolve a path from the file against the config directory.
    pub fn resolve(&self, p: &Path) -> PathBuf {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.base_dir.join(p)
        }
    }

    /// Semantic checks that serde cannot express.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::ConfigInvalid(m));
        if self.server.max_concurrency == 0 {
            return bad("server.max_concurrency must be at least 1".into());
        }
        if self.runtime.epoch_tick_ms == 0 {
            return bad("runtime.epoch_tick_ms must be at least 1".into());
        }
        if self.runtime.pool_size == 0 {
            return bad("runtime.pool_size must be at least 1".into());
        }
        if self.runtime.max_memory.0 < 1 << 16 {
            return bad("runtime.max_memory must be at least 64KiB (one wasm page)".into());
        }
        let mut names = BTreeSet::new();
        let mut routes = BTreeSet::new();
        for p in &self.plugins {
            let ctx = |m: &str| Error::ConfigInvalid(format!("plugin `{}`: {m}", p.name));
            if !valid_name(&p.name) {
                return Err(ctx(
                    "name must be 1-64 chars of [a-z0-9_-] starting with a letter",
                ));
            }
            if !names.insert(p.name.as_str()) {
                return Err(ctx("duplicate plugin name"));
            }
            let route = normalize_route(&p.route).ok_or_else(|| {
                ctx("route must start with `/` and contain only URL path characters")
            })?;
            if route.starts_with("/_plugbox") {
                return Err(ctx("routes under /_plugbox are reserved"));
            }
            if !routes.insert(route) {
                return Err(ctx("another plugin is already mounted on this route"));
            }
            let l = &p.limits;
            if l.timeout_ms == 0 {
                return Err(ctx("limits.timeout_ms must be at least 1"));
            }
            if l.memory > self.runtime.max_memory {
                return Err(ctx(&format!(
                    "limits.memory {} exceeds runtime.max_memory {}",
                    l.memory, self.runtime.max_memory
                )));
            }
            for name in p.grants.env.vars.keys().chain(&p.grants.env.inherit) {
                if name.is_empty() || name.contains('=') || name.contains('\0') {
                    return Err(ctx(&format!("invalid env var name `{name}`")));
                }
            }
            if let Some(http) = &p.grants.http {
                if http.allow.is_empty() {
                    return Err(ctx(
                        "grants.http.allow is empty; omit grants.http to deny outbound HTTP",
                    ));
                }
                for rule in &http.allow {
                    AllowRule::parse(rule)
                        .map_err(|e| ctx(&format!("allow rule `{rule}`: {e}")))?;
                }
            }
            if let Some(kv) = &p.grants.kv {
                if let Some(ns) = &kv.namespace
                    && !valid_name(ns)
                {
                    return Err(ctx("grants.kv.namespace must match the plugin-name rules"));
                }
                if kv.max_keys == 0 {
                    return Err(ctx("grants.kv.max_keys must be at least 1"));
                }
            }
        }
        Ok(())
    }
}

impl PluginConfig {
    /// The KV namespace this plugin uses, if it has a KV grant.
    pub fn kv_namespace(&self) -> Option<&str> {
        self.grants
            .kv
            .as_ref()
            .map(|kv| kv.namespace.as_deref().unwrap_or(&self.name))
    }
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Canonical form of a mount route: leading `/`, no trailing `/` (except the
/// root route), no empty or dot segments. Returns `None` if invalid.
pub fn normalize_route(route: &str) -> Option<String> {
    if !route.starts_with('/') {
        return None;
    }
    let segments: Vec<&str> = route.split('/').filter(|s| !s.is_empty()).collect();
    for s in &segments {
        if *s == "." || *s == ".." {
            return None;
        }
        let ok = s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~!$&'()*+,;=:@%".contains(c));
        if !ok {
            return None;
        }
    }
    Some(format!("/{}", segments.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config> {
        Config::parse(text, Path::new("/srv"))
    }

    const MINIMAL: &str = r#"
        [[plugins]]
        name = "hello"
        route = "/hello"
        component = "hello.wasm"
    "#;

    #[test]
    fn byte_sizes_parse_both_forms() {
        assert_eq!(ByteSize::parse("64KiB"), Some(ByteSize(65536)));
        assert_eq!(ByteSize::parse("32MiB"), Some(ByteSize(32 << 20)));
        assert_eq!(ByteSize::parse("1_024"), Some(ByteSize(1024)));
        assert_eq!(ByteSize::parse("2 GiB"), Some(ByteSize(2 << 30)));
        assert_eq!(ByteSize::parse("12XB"), None);
        assert_eq!(ByteSize::parse(""), None);
        assert_eq!(ByteSize::parse("99999999999999999999GiB"), None);
        assert_eq!(ByteSize(32 << 20).to_string(), "32MiB");
        assert_eq!(ByteSize(1536).to_string(), "1536B");
        assert_eq!(ByteSize(4 << 10).to_string(), "4KiB");
        assert_eq!(ByteSize(1 << 30).to_string(), "1GiB");
    }

    #[test]
    fn minimal_config_uses_safe_defaults() {
        let cfg = parse(MINIMAL).unwrap();
        let p = &cfg.plugins[0];
        assert_eq!(p.limits, Limits::default());
        assert!(p.grants.http.is_none(), "http must be denied by default");
        assert!(p.grants.kv.is_none(), "kv must be denied by default");
        assert!(p.grants.env.vars.is_empty());
        assert_eq!(cfg.resolve(&p.component), PathBuf::from("/srv/hello.wasm"));
        assert_eq!(
            cfg.resolve(Path::new("/abs.wasm")),
            PathBuf::from("/abs.wasm")
        );
        assert_eq!(p.kv_namespace(), None);
    }

    #[test]
    fn full_config_round_trips() {
        let cfg = parse(
            r#"
            [server]
            listen = "0.0.0.0:8000"
            max_concurrency = 8
            max_request_body = "64KiB"
            [runtime]
            instance_strategy = "on-demand"
            pool_size = 16
            max_memory = "16MiB"
            [[plugins]]
            name = "edge"
            route = "/api/"
            component = "edge.wasm"
            limits = { fuel = 0, timeout_ms = 20, memory = "8MiB" }
            [plugins.grants.env]
            vars = { REGION = "eu" }
            inherit = ["PATH"]
            [plugins.grants.http]
            allow = ["http://127.0.0.1:9000/*"]
            max_requests = 2
            [plugins.grants.kv]
            namespace = "shared"
            mode = "read-only"
        "#,
        )
        .unwrap();
        assert_eq!(cfg.server.max_request_body, ByteSize(65536));
        assert_eq!(cfg.runtime.instance_strategy, InstanceStrategy::OnDemand);
        let p = &cfg.plugins[0];
        assert_eq!(p.limits.fuel, 0);
        assert_eq!(p.limits.timeout(), Duration::from_millis(20));
        assert_eq!(p.kv_namespace(), Some("shared"));
        assert_eq!(p.grants.kv.as_ref().unwrap().mode, KvMode::ReadOnly);
        assert_eq!(p.grants.http.as_ref().unwrap().max_requests, 2);
        assert_eq!(p.grants.http.as_ref().unwrap().timeout_ms, 2000);
    }

    #[test]
    fn rejects_unknown_fields_and_bad_values() {
        let cases = [
            ("[server]\nlisten = \"nope\"", "invalid socket"),
            (
                "[[plugins]]\nname='a'\nroute='/a'\ncomponent='a.wasm'\nfuel=1",
                "unknown field",
            ),
            ("[runtime]\nepoch_tick_ms = 0", "epoch_tick_ms"),
            ("[runtime]\npool_size = 0", "pool_size"),
            ("[runtime]\nmax_memory = 100", "max_memory"),
            ("[server]\nmax_concurrency = 0", "max_concurrency"),
        ];
        for (text, needle) in cases {
            let err = parse(text).unwrap_err().to_string();
            assert!(err.contains(needle), "{text:?} -> {err}");
        }
    }

    #[test]
    fn rejects_semantic_errors() {
        let plugin = |extra: &str| {
            format!("[[plugins]]\nname = \"p\"\nroute = \"/p\"\ncomponent = \"p.wasm\"\n{extra}")
        };
        let cases = [
            (plugin("") + &plugin(""), "duplicate plugin name"),
            (
                plugin("") + "[[plugins]]\nname='q'\nroute='/p/'\ncomponent='q.wasm'\n",
                "already mounted",
            ),
            (
                "[[plugins]]\nname='Bad'\nroute='/x'\ncomponent='x'".into(),
                "name must be",
            ),
            (
                "[[plugins]]\nname='x'\nroute='x'\ncomponent='x'".into(),
                "route must start",
            ),
            (
                "[[plugins]]\nname='x'\nroute='/a/../b'\ncomponent='x'".into(),
                "route must",
            ),
            (
                "[[plugins]]\nname='x'\nroute='/_plugbox/x'\ncomponent='x'".into(),
                "reserved",
            ),
            (plugin("limits = { timeout_ms = 0 }"), "timeout_ms"),
            (
                plugin("limits = { memory = \"1GiB\" }"),
                "exceeds runtime.max_memory",
            ),
            (
                plugin("[plugins.grants.http]\nallow = []"),
                "allow is empty",
            ),
            (
                plugin("[plugins.grants.http]\nallow = ['ftp://x']"),
                "allow rule",
            ),
            (
                plugin("[plugins.grants.kv]\nnamespace = 'A B'"),
                "namespace",
            ),
            (plugin("[plugins.grants.kv]\nmax_keys = 0"), "max_keys"),
            (
                plugin("[plugins.grants.env]\nvars = { 'A=B' = 'x' }"),
                "invalid env var",
            ),
        ];
        for (text, needle) in cases {
            let err = parse(&text).unwrap_err().to_string();
            assert!(err.contains(needle), "{text:?} -> {err}");
        }
    }

    #[test]
    fn route_normalisation() {
        assert_eq!(normalize_route("/"), Some("/".into()));
        assert_eq!(normalize_route("//a//b/"), Some("/a/b".into()));
        assert_eq!(normalize_route("/a b"), None);
        assert_eq!(normalize_route("/./a"), None);
        assert_eq!(normalize_route("a"), None);
    }

    #[test]
    fn load_reports_path_on_errors() {
        let err = Config::load(Path::new("/definitely/not/here.toml")).unwrap_err();
        assert!(err.to_string().contains("/definitely/not/here.toml"));
        let dir = std::env::temp_dir().join(format!("plugbox-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("bad.toml");
        std::fs::write(&file, "[server\n").unwrap();
        let err = Config::load(&file).unwrap_err().to_string();
        assert!(err.contains("bad.toml"), "{err}");
        std::fs::write(&file, MINIMAL).unwrap();
        let cfg = Config::load(&file).unwrap();
        assert_eq!(cfg.base_dir, dir);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
