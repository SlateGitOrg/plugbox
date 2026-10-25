//! A deadline-aware `wasi:clocks/monotonic-clock`.
//!
//! Fuel and the epoch deadline are only checked while wasm code runs. A guest
//! that blocks inside `wasi:io/poll` (for example `std::thread::sleep`) runs
//! no wasm at all, so neither limit can interrupt it, and the host thread and
//! concurrency permit it holds stay taken for as long as the guest asked.
//!
//! In the plugbox sandbox the only pollables that can block are monotonic
//! clock subscriptions: sockets are refused at load time, no directory is
//! preopened, stdin is empty, stdout/stderr are in-memory, and outbound HTTP
//! is a host call already bounded by the request deadline. So this module
//! replaces the four monotonic-clock functions wasmtime-wasi links, and every
//! `subscribe-duration` / `subscribe-instant` pollable it creates fires no
//! later than the request deadline. When a pollable fires *because of* the
//! deadline (the guest asked for a later time), it raises a flag that
//! [`crate::Runtime::invoke`] turns into a `deadline-exceeded` trap, so a
//! cut-short sleep can never quietly produce a response after the deadline.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use wasmtime::component::{HasData, Linker, Resource, ResourceTable};
use wasmtime_wasi::p2::bindings::clocks::monotonic_clock;
use wasmtime_wasi::p2::{DynPollable, Pollable, subscribe};

use crate::host::HostState;

/// Per-request clock state: the clock's zero point, the request deadline and
/// the "a sleep was cut at the deadline" flag.
#[derive(Clone, Debug)]
pub struct SleepGuard {
    origin: Instant,
    deadline: Instant,
    cut: Arc<AtomicBool>,
}

impl SleepGuard {
    /// A guard whose clock starts now and caps every wait at `deadline`.
    pub fn new(deadline: Instant) -> SleepGuard {
        SleepGuard {
            origin: Instant::now(),
            deadline,
            cut: Arc::new(AtomicBool::new(false)),
        }
    }

    /// True once a guest wait was ended by the request deadline rather than
    /// by the time the guest asked for.
    pub fn was_cut(&self) -> bool {
        self.cut.load(Ordering::Relaxed)
    }

    /// Monotonic-clock reading: nanoseconds since the guard was created.
    fn now_nanos(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// The wait the host will actually perform for a guest request of
    /// `requested`, and whether that is shorter than what was asked.
    fn plan(&self, requested: Duration, now: Instant) -> (Duration, bool) {
        let remaining = self.deadline.saturating_duration_since(now);
        if requested > remaining {
            (remaining, true)
        } else {
            (requested, false)
        }
    }

    fn sleep(&self, requested: Duration) -> GuardedSleep {
        let now = Instant::now();
        let (wait, clamped) = self.plan(requested, now);
        GuardedSleep {
            until: tokio::time::Instant::from_std(now + wait),
            zero: requested.is_zero(),
            yielded: false,
            cut: clamped.then(|| self.cut.clone()),
        }
    }
}

/// The pollable behind a clock subscription.
struct GuardedSleep {
    until: tokio::time::Instant,
    /// The guest asked for a zero-length wait (a non-blocking poll).
    zero: bool,
    yielded: bool,
    /// Set when this wait was shortened to the request deadline.
    cut: Option<Arc<AtomicBool>>,
}

#[wasmtime_wasi::async_trait]
impl Pollable for GuardedSleep {
    async fn ready(&mut self) {
        if self.zero {
            // Same as wasmtime-wasi: yield once so a guest polling in a busy
            // loop cannot starve the tokio reactor.
            if !self.yielded {
                self.yielded = true;
                tokio::task::yield_now().await;
            }
            return;
        }
        tokio::time::sleep_until(self.until).await;
        if let Some(cut) = &self.cut {
            cut.store(true, Ordering::Relaxed);
        }
    }
}

/// The view the monotonic-clock host functions operate on.
pub struct GuardedClockView<'a> {
    table: &'a mut ResourceTable,
    guard: &'a SleepGuard,
}

impl<'a> GuardedClockView<'a> {
    pub(crate) fn new(table: &'a mut ResourceTable, guard: &'a SleepGuard) -> Self {
        GuardedClockView { table, guard }
    }

    fn subscribe(&mut self, requested: Duration) -> wasmtime::Result<Resource<DynPollable>> {
        let sleep = self.table.push(self.guard.sleep(requested))?;
        subscribe(self.table, sleep)
    }
}

impl monotonic_clock::Host for GuardedClockView<'_> {
    fn now(&mut self) -> wasmtime::Result<monotonic_clock::Instant> {
        Ok(self.guard.now_nanos())
    }

    fn resolution(&mut self) -> wasmtime::Result<monotonic_clock::Duration> {
        Ok(1)
    }

    fn subscribe_instant(
        &mut self,
        when: monotonic_clock::Instant,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        let now = self.guard.now_nanos();
        self.subscribe(Duration::from_nanos(when.saturating_sub(now)))
    }

    fn subscribe_duration(
        &mut self,
        duration: monotonic_clock::Duration,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        self.subscribe(Duration::from_nanos(duration))
    }
}

struct GuardedClock;

impl HasData for GuardedClock {
    type Data<'a> = GuardedClockView<'a>;
}

/// Replace the monotonic clock that `wasmtime_wasi::p2::add_to_linker_sync`
/// linked with the deadline-aware one. Must run after WASI is linked.
pub fn shadow_monotonic_clock(linker: &mut Linker<HostState>) -> wasmtime::Result<()> {
    linker.allow_shadowing(true);
    let result =
        monotonic_clock::add_to_linker::<HostState, GuardedClock>(linker, HostState::clock_view);
    linker.allow_shadowing(false);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn waits_are_capped_at_the_deadline() {
        let now = Instant::now();
        let g = SleepGuard {
            origin: now,
            deadline: now + 50 * MS,
            cut: Arc::new(AtomicBool::new(false)),
        };
        assert_eq!(g.plan(10 * MS, now), (10 * MS, false));
        assert_eq!(g.plan(50 * MS, now), (50 * MS, false));
        assert_eq!(g.plan(Duration::from_secs(3600), now), (50 * MS, true));
        assert_eq!(g.plan(Duration::MAX, now), (50 * MS, true));
        // After the deadline every non-zero wait is cut to nothing.
        let late = now + 60 * MS;
        assert_eq!(g.plan(MS, late), (Duration::ZERO, true));
        assert_eq!(g.plan(Duration::ZERO, late), (Duration::ZERO, false));
    }

    #[test]
    fn cut_flag_is_raised_only_when_the_deadline_ends_the_wait() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let g = SleepGuard::new(Instant::now() + 30 * MS);
        rt.block_on(async {
            let mut short = g.sleep(MS);
            assert!(short.cut.is_none());
            short.ready().await;
            assert!(!g.was_cut());

            let mut zero = g.sleep(Duration::ZERO);
            zero.ready().await;
            zero.ready().await;
            assert!(!g.was_cut());

            let started = Instant::now();
            let mut long = g.sleep(Duration::from_secs(3600));
            long.ready().await;
            assert!(started.elapsed() < Duration::from_secs(1));
            assert!(g.was_cut());
        });
        assert!(g.now_nanos() > 0);
    }
}
