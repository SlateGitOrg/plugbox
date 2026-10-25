//! Host side of the WIT world: generated bindings, the per-request store
//! state, and the implementations of every imported interface.
//!
//! One [`HostState`] is created per request and dropped with the store when
//! the request ends, so nothing a guest does can leak into another request
//! except through the explicitly shared KV capability.

use std::sync::Arc;
use std::time::Instant;

use wasmtime::component::{HasSelf, Linker, ResourceTable};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

use crate::capability::kv::{KvError as HostKvError, KvStore};
use crate::capability::{Capabilities, Capability};
use crate::clock::{GuardedClockView, SleepGuard};
use crate::limits::MemoryLimiter;
use crate::metrics::Metrics;
use crate::outbound::{CallBudget, FetchError, Outbound};
use crate::stdio::CappedPipe;

wasmtime::component::bindgen!({
    world: "plugin",
    path: "wit",
});

use self::plugbox::host::kv::KvError;
use self::plugbox::host::log::Level;
use self::plugbox::host::outbound_http::{HttpError, OutboundRequest, OutboundResponse};
pub use exports::plugbox::host::handler::{Request, Response};

/// Longest guest log message kept; longer ones are truncated.
pub const MAX_LOG_MESSAGE: usize = 1024;

/// Per-request store data.
pub struct HostState {
    wasi: WasiCtx,
    table: ResourceTable,
    pub(crate) limiter: MemoryLimiter,
    plugin: Arc<str>,
    caps: Arc<Capabilities>,
    kv: Arc<KvStore>,
    outbound: Outbound,
    metrics: Arc<Metrics>,
    budget: CallBudget,
    deadline: Instant,
    pub(crate) clock: SleepGuard,
    max_log_lines: u32,
    log_lines: u32,
    pub(crate) stdio: CappedPipe,
    pub(crate) denials: u32,
}

/// Everything needed to build a [`HostState`].
pub struct HostContext {
    pub plugin: Arc<str>,
    pub caps: Arc<Capabilities>,
    pub kv: Arc<KvStore>,
    pub outbound: Outbound,
    pub metrics: Arc<Metrics>,
    pub memory_limit: usize,
    pub deadline: Instant,
    pub max_log_lines: u32,
    pub max_stdio: usize,
}

impl HostState {
    /// Fresh per-request state. The WASI context is locked down: no args, no
    /// environment, no preopened directories, no sockets, and stdout/stderr
    /// go to a capped in-memory buffer.
    pub fn new(ctx: HostContext) -> HostState {
        let stdio = CappedPipe::new(ctx.max_stdio);
        let wasi = WasiCtx::builder()
            .stdout(stdio.clone())
            .stderr(stdio.clone())
            .allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false)
            .build();
        HostState {
            wasi,
            table: ResourceTable::new(),
            limiter: MemoryLimiter::new(ctx.memory_limit),
            plugin: ctx.plugin,
            caps: ctx.caps,
            kv: ctx.kv,
            outbound: ctx.outbound,
            metrics: ctx.metrics,
            budget: CallBudget::default(),
            deadline: ctx.deadline,
            clock: SleepGuard::new(ctx.deadline),
            max_log_lines: ctx.max_log_lines,
            log_lines: 0,
            stdio,
            denials: 0,
        }
    }

    fn deny(&mut self, cap: Capability) {
        self.denials += 1;
        let label = cap.to_string();
        self.metrics
            .capability_denials
            .inc(&[&self.plugin, label.as_str()]);
        tracing::debug!(plugin = %self.plugin, capability = %cap, "capability denied");
    }

    /// Outbound calls made so far in this request.
    pub fn outbound_calls(&self) -> u32 {
        self.budget.used
    }

    /// Guest log lines emitted (including dropped ones).
    pub fn log_lines(&self) -> u32 {
        self.log_lines
    }

    /// True when a guest wait in `wasi:io/poll` was ended by the request
    /// deadline (see [`crate::clock`]).
    pub fn sleep_cut(&self) -> bool {
        self.clock.was_cut()
    }

    pub(crate) fn clock_view(&mut self) -> GuardedClockView<'_> {
        GuardedClockView::new(&mut self.table, &self.clock)
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

/// Register WASI (sync) and the plugbox interfaces. The stock monotonic
/// clock is replaced by the deadline-capped one from [`crate::clock`], so no
/// guest wait in `wasi:io/poll` can outlive the request deadline.
pub fn add_to_linker(linker: &mut Linker<HostState>) -> wasmtime::Result<()> {
    wasmtime_wasi::p2::add_to_linker_sync(linker)?;
    crate::clock::shadow_monotonic_clock(linker)?;
    Plugin::add_to_linker::<HostState, HasSelf<HostState>>(linker, |s| s)
}

impl self::plugbox::host::types::Host for HostState {}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Escape control characters so a guest cannot forge extra lines (or
/// terminal escapes) in the host's log stream.
fn sanitize(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(char::is_control) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

impl self::plugbox::host::log::Host for HostState {
    fn log(&mut self, level: Level, message: String) {
        self.log_lines = self.log_lines.saturating_add(1);
        if self.log_lines > self.max_log_lines {
            self.metrics.guest_logs_dropped.inc(&[&self.plugin]);
            return;
        }
        let msg = sanitize(truncate(&message, MAX_LOG_MESSAGE));
        let plugin = &*self.plugin;
        match level {
            Level::Trace => tracing::trace!(target: "plugbox::guest", plugin, "{msg}"),
            Level::Debug => tracing::debug!(target: "plugbox::guest", plugin, "{msg}"),
            Level::Info => tracing::info!(target: "plugbox::guest", plugin, "{msg}"),
            Level::Warn => tracing::warn!(target: "plugbox::guest", plugin, "{msg}"),
            Level::Error => tracing::error!(target: "plugbox::guest", plugin, "{msg}"),
        }
    }
}

impl self::plugbox::host::env::Host for HostState {
    fn get(&mut self, name: String) -> Option<String> {
        let value = self.caps.env.get(&name).cloned();
        if value.is_none() {
            self.deny(Capability::Env);
        }
        value
    }

    fn names(&mut self) -> Vec<String> {
        self.caps.env.keys().cloned().collect()
    }
}

impl From<FetchError> for HttpError {
    fn from(e: FetchError) -> Self {
        match e {
            FetchError::NotGranted => HttpError::NotGranted,
            FetchError::Forbidden(m) => HttpError::Forbidden(m),
            FetchError::InvalidUrl(m) => HttpError::InvalidUrl(m),
            FetchError::QuotaExceeded => HttpError::QuotaExceeded,
            FetchError::Timeout => HttpError::Timeout,
            FetchError::Transport(m) => HttpError::Transport(m),
            FetchError::TooLarge => HttpError::TooLarge,
        }
    }
}

impl self::plugbox::host::outbound_http::Host for HostState {
    fn fetch(&mut self, req: OutboundRequest) -> Result<OutboundResponse, HttpError> {
        let result = self.outbound.fetch(
            self.caps.http.as_ref(),
            &mut self.budget,
            crate::outbound::FetchRequest {
                method: req.method,
                url: req.url,
                headers: req.headers,
                body: req.body,
            },
            self.deadline,
        );
        let label = match &result {
            Ok(_) => "ok",
            Err(e) => e.label(),
        };
        self.metrics.outbound_requests.inc(&[&self.plugin, label]);
        match result {
            Ok(r) => Ok(OutboundResponse {
                status: r.status,
                headers: r.headers,
                body: r.body,
            }),
            Err(e) => {
                if e.is_denial() {
                    self.deny(Capability::Http);
                }
                tracing::debug!(plugin = %self.plugin, error = ?e, "outbound fetch failed");
                Err(e.into())
            }
        }
    }
}

impl From<HostKvError> for KvError {
    fn from(e: HostKvError) -> Self {
        match e {
            HostKvError::NotGranted => KvError::NotGranted,
            HostKvError::ReadOnly => KvError::ReadOnly,
            HostKvError::QuotaExceeded(m) => KvError::QuotaExceeded(m),
            HostKvError::InvalidKey(m) => KvError::InvalidKey(m),
            HostKvError::NotANumber => KvError::NotANumber,
        }
    }
}

impl HostState {
    fn with_kv<R>(
        &mut self,
        f: impl FnOnce(&KvStore, &crate::capability::kv::KvGrantSpec) -> Result<R, HostKvError>,
    ) -> Result<R, KvError> {
        let result = match self.caps.kv.as_ref() {
            Some(grant) => f(&self.kv, grant),
            None => Err(HostKvError::NotGranted),
        };
        if matches!(result, Err(HostKvError::NotGranted | HostKvError::ReadOnly)) {
            self.deny(Capability::Kv);
        }
        result.map_err(KvError::from)
    }
}

impl self::plugbox::host::kv::Host for HostState {
    fn get(&mut self, key: String) -> Result<Option<Vec<u8>>, KvError> {
        self.with_kv(|kv, g| kv.get(g, &key))
    }

    fn set(&mut self, key: String, value: Vec<u8>) -> Result<(), KvError> {
        self.with_kv(|kv, g| kv.set(g, &key, value))
    }

    fn delete(&mut self, key: String) -> Result<bool, KvError> {
        self.with_kv(|kv, g| kv.delete(g, &key))
    }

    fn list_keys(&mut self, prefix: String, limit: u32) -> Result<Vec<String>, KvError> {
        self.with_kv(|kv, g| Ok(kv.list_keys(g, &prefix, limit)))
    }

    fn increment(&mut self, key: String, delta: i64) -> Result<i64, KvError> {
        self.with_kv(|kv, g| kv.increment(g, &key, delta))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_respects_char_boundaries() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello", 3), "hel");
        assert_eq!(truncate("héllo", 2), "h");
    }

    #[test]
    fn control_characters_are_escaped() {
        assert!(matches!(
            sanitize("plain"),
            std::borrow::Cow::Borrowed("plain")
        ));
        assert_eq!(
            sanitize("ok\nlevel=ERROR forged\u{1b}[2J"),
            "ok\\nlevel=ERROR forged\\u{1b}[2J"
        );
    }
}
