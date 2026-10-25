//! Wasmtime engine construction and the epoch ticker.
//!
//! One engine is shared by every plugin. It always enables both CPU limits:
//!
//! * **fuel** — deterministic instruction budget, checked at loop headers and
//!   function entries; immune to host scheduling noise.
//! * **epoch interruption** — wall-clock deadline. A background thread bumps
//!   the engine epoch every `epoch_tick`; each store traps once its deadline
//!   (in ticks) has passed. This also bounds time spent *between* fuel checks
//!   and covers plugins that opt out of fuel.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use wasmtime::{Config, Engine, InstanceAllocationStrategy, OptLevel, PoolingAllocationConfig};

use crate::config::InstanceStrategy;
use crate::error::{Error, Result};
use crate::limits;

/// Engine-level settings (from `[runtime]`).
#[derive(Clone, Debug, PartialEq)]
pub struct EngineSettings {
    pub strategy: InstanceStrategy,
    /// Component instances the pool can hold concurrently.
    pub pool_size: u32,
    /// Largest linear memory any plugin may use.
    pub max_memory: usize,
    pub epoch_tick: Duration,
}

impl Default for EngineSettings {
    fn default() -> Self {
        EngineSettings {
            strategy: InstanceStrategy::Pooling,
            pool_size: 128,
            max_memory: 64 << 20,
            epoch_tick: Duration::from_millis(5),
        }
    }
}

/// Guard region after each linear memory.
const GUARD: u64 = 64 << 10;
/// Core modules per component we size the pool for (Rust `wasm32-wasip2`
/// components contain a handful: the program, libc shims, glue).
const CORE_PER_COMPONENT: u32 = 16;

/// Build the shared engine.
pub fn build_engine(s: &EngineSettings) -> Result<Engine> {
    let mut cfg = Config::new();
    cfg.wasm_component_model(true)
        .consume_fuel(true)
        .epoch_interruption(true)
        .cranelift_opt_level(OptLevel::Speed)
        .max_wasm_stack(1 << 20)
        // Reserve exactly the largest allowed memory (plus a guard) instead of
        // the 4 GiB default, so a pool of hundreds of slots stays a few GiB of
        // address space. Bounds checks become explicit for larger heaps.
        .memory_reservation(s.max_memory as u64)
        .memory_guard_size(GUARD)
        .memory_reservation_for_growth(0)
        .memory_init_cow(true);
    if s.strategy == InstanceStrategy::Pooling {
        let n = s.pool_size;
        let mut pool = PoolingAllocationConfig::default();
        pool.total_component_instances(n)
            .total_core_instances(n.saturating_mul(CORE_PER_COMPONENT))
            .max_core_instances_per_component(CORE_PER_COMPONENT)
            .total_memories(n.saturating_mul(2))
            .max_memories_per_component(limits::MAX_MEMORIES as u32)
            .max_memories_per_module(1)
            .total_tables(n.saturating_mul(CORE_PER_COMPONENT))
            .max_tables_per_component(CORE_PER_COMPONENT)
            .max_memory_size(s.max_memory)
            .max_unused_warm_slots(n);
        cfg.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));
    } else {
        cfg.allocation_strategy(InstanceAllocationStrategy::OnDemand);
    }
    Engine::new(&cfg).map_err(|e| Error::Engine(format!("{e:#}")))
}

/// Deadline in epoch ticks for a wall-clock budget: rounded up, plus one
/// tick because the current tick may be about to end.
pub fn deadline_ticks(timeout: Duration, tick: Duration) -> u64 {
    let tick_ns = tick.as_nanos().max(1);
    let ticks = timeout.as_nanos().div_ceil(tick_ns);
    u64::try_from(ticks)
        .unwrap_or(u64::MAX - 1)
        .saturating_add(1)
}

/// Background thread that advances the engine epoch.
#[derive(Debug)]
pub struct EpochTicker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl EpochTicker {
    /// Start ticking `engine` every `tick`.
    pub fn start(engine: Engine, tick: Duration) -> EpochTicker {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handle = std::thread::Builder::new()
            .name("plugbox-epoch".into())
            .spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    std::thread::park_timeout(tick);
                    engine.increment_epoch();
                }
            })
            .expect("spawn epoch ticker thread");
        EpochTicker {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            h.thread().unpark();
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_rounding() {
        let tick = Duration::from_millis(5);
        assert_eq!(deadline_ticks(Duration::from_millis(0), tick), 1);
        assert_eq!(deadline_ticks(Duration::from_millis(1), tick), 2);
        assert_eq!(deadline_ticks(Duration::from_millis(10), tick), 3);
        assert_eq!(deadline_ticks(Duration::from_millis(11), tick), 4);
        assert_eq!(
            deadline_ticks(Duration::MAX, Duration::from_nanos(1)),
            u64::MAX
        );
    }

    #[test]
    fn both_strategies_build_and_tick() {
        for strategy in [InstanceStrategy::Pooling, InstanceStrategy::OnDemand] {
            let s = EngineSettings {
                strategy,
                pool_size: 4,
                ..EngineSettings::default()
            };
            let engine = build_engine(&s).unwrap();
            assert_eq!(
                engine.pooling_allocator_metrics().is_some(),
                strategy == InstanceStrategy::Pooling
            );
            let ticker = EpochTicker::start(engine, Duration::from_millis(1));
            std::thread::sleep(Duration::from_millis(5));
            drop(ticker); // must join promptly
        }
    }
}
