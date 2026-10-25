//! Per-instance memory accounting.
//!
//! Wasmtime asks a [`ResourceLimiter`] before every linear-memory or table
//! growth, including the initial allocation at instantiation. The
//! [`MemoryLimiter`] enforces one budget across *all* memories of a
//! component (a component may contain several core modules, each with its
//! own memory), and remembers that it refused a growth so the runtime can
//! report the resulting guest abort as a memory-limit violation rather than
//! as a generic trap.

use wasmtime::ResourceLimiter;

/// Table elements allowed per instance (each costs a pointer).
pub const MAX_TABLE_ELEMENTS: usize = 100_000;
/// Core instances / tables / memories allowed per store.
pub const MAX_INSTANCES: usize = 64;
pub const MAX_TABLES: usize = 64;
pub const MAX_MEMORIES: usize = 16;

/// Tracks and caps the memory of one store.
#[derive(Debug, Clone)]
pub struct MemoryLimiter {
    limit: usize,
    used: usize,
    peak: usize,
    /// Bytes reserved by the most recent permitted growth, released again if
    /// the engine reports that the growth failed after all.
    pending: usize,
    denied: Option<usize>,
}

impl MemoryLimiter {
    /// A limiter with a total budget of `limit` bytes.
    pub fn new(limit: usize) -> MemoryLimiter {
        MemoryLimiter {
            limit,
            used: 0,
            peak: 0,
            pending: 0,
            denied: None,
        }
    }

    /// Bytes of linear memory currently committed.
    pub fn used(&self) -> usize {
        self.used
    }

    /// Highest `used` observed.
    pub fn peak(&self) -> usize {
        self.peak
    }

    /// The total size requested by the first refused growth, if any.
    pub fn denied(&self) -> Option<usize> {
        self.denied
    }
}

impl ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let delta = desired.saturating_sub(current);
        let over_budget = self.used.saturating_add(delta) > self.limit;
        let over_max = maximum.is_some_and(|m| desired > m);
        if over_budget || over_max {
            self.denied.get_or_insert(self.used.saturating_add(delta));
            self.pending = 0;
            return Ok(false);
        }
        self.used += delta;
        self.peak = self.peak.max(self.used);
        self.pending = delta;
        Ok(true)
    }

    fn memory_grow_failed(&mut self, _error: wasmtime::Error) -> wasmtime::Result<()> {
        self.used = self.used.saturating_sub(self.pending);
        self.pending = 0;
        Ok(())
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= MAX_TABLE_ELEMENTS && maximum.is_none_or(|m| desired <= m))
    }

    fn instances(&self) -> usize {
        MAX_INSTANCES
    }

    fn tables(&self) -> usize {
        MAX_TABLES
    }

    fn memories(&self) -> usize {
        MAX_MEMORIES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_spans_all_memories() {
        let mut l = MemoryLimiter::new(1000);
        assert!(l.memory_growing(0, 600, None).unwrap());
        assert!(
            l.memory_growing(0, 300, None).unwrap(),
            "second memory shares the budget"
        );
        assert!(!l.memory_growing(300, 500, None).unwrap());
        assert_eq!(l.denied(), Some(1100));
        assert_eq!(l.used(), 900);
        assert_eq!(l.peak(), 900);
        assert!(l.memory_growing(600, 700, None).unwrap());
        assert_eq!(l.denied(), Some(1100), "first denial is kept");
    }

    #[test]
    fn failed_growth_is_refunded() {
        let mut l = MemoryLimiter::new(1000);
        assert!(l.memory_growing(0, 400, None).unwrap());
        l.memory_grow_failed(wasmtime::format_err!("os said no"))
            .unwrap();
        assert_eq!(l.used(), 0);
        assert!(
            !l.memory_growing(0, 10, Some(5)).unwrap(),
            "declared maximum is respected"
        );
    }

    #[test]
    fn table_and_count_limits() {
        let mut l = MemoryLimiter::new(0);
        assert!(l.table_growing(0, 10, None).unwrap());
        assert!(!l.table_growing(0, MAX_TABLE_ELEMENTS + 1, None).unwrap());
        assert!(!l.table_growing(0, 10, Some(5)).unwrap());
        assert_eq!(l.instances(), MAX_INSTANCES);
        assert_eq!(l.tables(), MAX_TABLES);
        assert_eq!(l.memories(), MAX_MEMORIES);
    }
}
