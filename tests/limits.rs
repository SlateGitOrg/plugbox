//! Every sandbox limit trips, the trap is classified correctly, and the host
//! stays healthy afterwards.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use plugbox::{Outcome, Registry, TrapKind};

fn hostile_config(upstream: std::net::SocketAddr) -> String {
    let hostile = lit(&wasm("hostile"));
    let hello = lit(&wasm("hello"));
    format!(
        r#"
[[plugins]]
name = "hostile"
route = "/hostile"
component = {hostile}
limits = {{ fuel = 100_000_000, timeout_ms = 3000, memory = "16MiB", max_log_lines = 5, max_stdio = "1KiB" }}
[plugins.grants.http]
allow = ["http://{upstream}/*"]
max_requests = 3

[[plugins]]
name = "hostile-nofuel"
route = "/nofuel"
component = {hostile}
limits = {{ fuel = 0, timeout_ms = 60 }}

[[plugins]]
name = "hello"
route = "/hello"
component = {hello}
[plugins.grants.env]
vars = {{ GREETING = "hi" }}
"#
    )
}

struct Env {
    _dir: TempDir,
    reg: Arc<Registry>,
    upstream: std::net::SocketAddr,
}

fn env() -> Env {
    let dir = TempDir::new("limits");
    let upstream = spawn_upstream();
    let reg = registry(&dir, runtime(), &hostile_config(upstream));
    Env {
        _dir: dir,
        reg,
        upstream,
    }
}

impl Env {
    fn call(&self, plugin: &str, path: &str, query: &str) -> plugbox::Invocation {
        let p = self.reg.snapshot().get(plugin).unwrap();
        self.reg.runtime().invoke(&p, &request("GET", path, query))
    }

    /// The good plugin still answers and nothing is left allocated.
    fn assert_healthy(&self) {
        let inv = self.call("hello", "/", "name=after");
        match &inv.outcome {
            Outcome::Response(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(body(r), "hi, after!\n");
            }
            other => panic!("host unhealthy after misbehaviour: {other:?}"),
        }
        let rt = self.reg.runtime();
        assert_eq!(rt.metrics().in_flight.get(), 0);
        assert_eq!(
            rt.pool_live_instances(),
            Some(0),
            "every pool slot must be returned"
        );
    }
}

fn trap_kind(inv: &plugbox::Invocation) -> TrapKind {
    match &inv.outcome {
        Outcome::Trap { kind, .. } => *kind,
        other => panic!("expected a trap, got {other:?}"),
    }
}

#[test]
fn infinite_loop_trips_fuel() {
    let e = env();
    let inv = e.call("hostile", "/loop", "");
    assert_eq!(trap_kind(&inv), TrapKind::FuelExhausted);
    assert_eq!(inv.outcome.http_status(), 504);
    assert_eq!(
        inv.stats.fuel_consumed, 100_000_000,
        "the whole budget is consumed"
    );
    assert!(
        inv.stats.total < Duration::from_secs(3),
        "fuel trips before the deadline"
    );
    assert_eq!(
        e.reg
            .runtime()
            .metrics()
            .traps
            .get(&["hostile", "fuel-exhausted"]),
        1
    );
    e.assert_healthy();
}

#[test]
fn infinite_loop_trips_epoch_deadline_without_fuel() {
    let e = env();
    let started = Instant::now();
    let inv = e.call("hostile-nofuel", "/loop", "");
    let elapsed = started.elapsed();
    assert_eq!(trap_kind(&inv), TrapKind::DeadlineExceeded);
    assert_eq!(inv.outcome.error_label(), Some("deadline-exceeded"));
    assert!(elapsed >= Duration::from_millis(60), "{elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(1000),
        "deadline overshoot: {elapsed:?}"
    );
    e.assert_healthy();
}

#[test]
fn memory_bomb_trips_memory_limit() {
    let e = env();
    let inv = e.call("hostile", "/bomb", "");
    assert_eq!(trap_kind(&inv), TrapKind::MemoryLimit);
    assert_eq!(inv.outcome.http_status(), 502);
    assert!(
        inv.stats.memory_peak <= 16 << 20,
        "peak {}",
        inv.stats.memory_peak
    );
    assert!(
        inv.stats.memory_peak > 8 << 20,
        "the bomb really allocated: {}",
        inv.stats.memory_peak
    );
    e.assert_healthy();
}

#[test]
fn unbounded_recursion_trips_stack_limit() {
    let e = env();
    assert_eq!(
        trap_kind(&e.call("hostile", "/recurse", "")),
        TrapKind::StackOverflow
    );
    e.assert_healthy();
}

#[test]
fn shadow_stack_overflow_is_a_contained_memory_fault() {
    let e = env();
    let inv = e.call("hostile", "/stack", "");
    assert_eq!(trap_kind(&inv), TrapKind::MemoryFault);
    assert!(
        matches!(&inv.outcome, Outcome::Trap { detail, .. } if detail.contains("out of bounds"))
    );
    e.assert_healthy();
}

#[test]
fn panic_is_a_contained_guest_abort() {
    let e = env();
    let inv = e.call("hostile", "/panic", "");
    assert_eq!(trap_kind(&inv), TrapKind::GuestAbort);
    assert!(
        inv.stats.stdio.contains("panicked on purpose"),
        "{}",
        inv.stats.stdio
    );
    e.assert_healthy();
}

#[test]
fn forbidden_host_is_refused_without_trapping() {
    let e = env();
    let inv = e.call("hostile", "/forbidden", "");
    let Outcome::Response(r) = &inv.outcome else {
        panic!("{:?}", inv.outcome)
    };
    assert_eq!(r.status, 403);
    assert!(
        body(r).starts_with("forbidden: http://169.254.169.254"),
        "{}",
        body(r)
    );
    let m = e.reg.runtime().metrics();
    assert_eq!(m.capability_denials.get(&["hostile", "http"]), 1);
    assert_eq!(m.outbound_requests.get(&["hostile", "forbidden"]), 1);
    // Classic allow-list bypass shapes are refused as invalid URLs.
    for url in [
        "http://127.0.0.1@169.254.169.254/",
        "http://2852039166/",
        "http://169.254.169.254.nip.io@x/",
    ] {
        let inv = e.call("hostile", "/forbidden", &format!("url={url}"));
        let Outcome::Response(r) = &inv.outcome else {
            panic!("{:?}", inv.outcome)
        };
        assert!(body(r).starts_with("invalid-url"), "{url}: {}", body(r));
    }
    e.assert_healthy();
}

#[test]
fn ungranted_env_files_and_kv_are_invisible() {
    let e = env();
    let Outcome::Response(r) = e.call("hostile", "/secret", "").outcome else {
        panic!()
    };
    let text = body(&r);
    assert!(text.contains("\"granted_secret\":false"), "{text}");
    assert!(text.contains("\"wasi_env\":[]"), "host env leaked: {text}");
    assert!(
        text.contains("\"etc_passwd\":\"Err("),
        "filesystem reachable: {text}"
    );

    let Outcome::Response(r) = e.call("hostile", "/kv", "").outcome else {
        panic!()
    };
    assert_eq!(r.status, 403);
    assert!(body(&r).contains("NotGranted"), "{}", body(&r));
    let m = e.reg.runtime().metrics();
    assert_eq!(m.capability_denials.get(&["hostile", "kv"]), 1);
    assert!(m.capability_denials.get(&["hostile", "env"]) >= 1);
    e.assert_healthy();
}

#[test]
fn outbound_call_budget_is_enforced() {
    let e = env();
    let url = format!("http://{}/x", e.upstream);
    let inv = e.call("hostile", "/fetch-flood", &format!("url={url}"));
    let Outcome::Response(r) = &inv.outcome else {
        panic!("{:?}", inv.outcome)
    };
    assert_eq!(body(r), "3 calls succeeded, then: quota-exceeded\n");
    assert_eq!(inv.stats.outbound_calls, 3, "refused calls are not charged");
    e.assert_healthy();
}

#[test]
fn log_and_stdout_floods_are_capped() {
    let e = env();
    let inv = e.call("hostile", "/log-flood", "");
    assert!(
        matches!(&inv.outcome, Outcome::Response(r) if r.status == 200),
        "{:?}",
        inv.outcome
    );
    assert_eq!(inv.stats.log_lines, 10_000);
    assert_eq!(inv.stats.stdio.len(), 1024);
    assert!(inv.stats.stdio_dropped > 1_000_000);
    assert_eq!(
        e.reg
            .runtime()
            .metrics()
            .guest_logs_dropped
            .get(&["hostile"]),
        10_000 - 5
    );
    e.assert_healthy();
}

#[test]
fn oversized_response_is_replaced() {
    let e = env();
    let inv = e.call("hostile", "/huge-response", "bytes=2000000");
    assert!(
        matches!(inv.outcome, Outcome::InvalidResponse(_)),
        "{:?}",
        inv.outcome
    );
    assert_eq!(inv.outcome.http_status(), 502);
    let ok = e.call("hostile", "/huge-response", "bytes=1000");
    assert!(matches!(&ok.outcome, Outcome::Response(r) if r.body.len() == 1000));
    e.assert_healthy();
}

#[test]
fn work_under_the_deadline_succeeds() {
    let e = env();
    let inv = e.call("hostile-nofuel", "/spin", "ms=10");
    assert!(
        matches!(&inv.outcome, Outcome::Response(r) if r.status == 200),
        "{:?}",
        inv.outcome
    );
}

/// Hostile requests running concurrently with good ones: every good request
/// succeeds, every hostile one trips, and the pool drains to zero.
#[test]
fn host_stays_healthy_under_concurrent_abuse() {
    let e = Arc::new(env());
    let routes = ["/loop", "/bomb", "/recurse", "/panic"];
    let mut handles = Vec::new();
    for i in 0..8 {
        let e = e.clone();
        handles.push(std::thread::spawn(move || {
            let route = routes[i % routes.len()];
            for _ in 0..3 {
                let inv = e.call("hostile", route, "");
                assert!(
                    matches!(inv.outcome, Outcome::Trap { .. }),
                    "{route}: {:?}",
                    inv.outcome
                );
            }
            0usize
        }));
    }
    for _ in 0..4 {
        let e = e.clone();
        handles.push(std::thread::spawn(move || {
            let mut ok = 0;
            for _ in 0..25 {
                if let Outcome::Response(r) = e.call("hello", "/", "").outcome {
                    assert_eq!(r.status, 200);
                    ok += 1;
                }
            }
            ok
        }));
    }
    let good: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(good, 100, "every well-behaved request must succeed");
    let m = e.reg.runtime().metrics();
    assert_eq!(m.traps.get(&["hostile", "fuel-exhausted"]), 6);
    assert_eq!(m.traps.get(&["hostile", "memory-limit"]), 6);
    assert_eq!(m.traps.get(&["hostile", "stack-overflow"]), 6);
    assert_eq!(m.traps.get(&["hostile", "guest-abort"]), 6);
    e.assert_healthy();
}

#[test]
fn many_sequential_traps_do_not_leak_pool_slots() {
    let e = env();
    for _ in 0..100 {
        let inv = e.call("hostile", "/panic", "");
        assert_eq!(trap_kind(&inv), TrapKind::GuestAbort);
    }
    e.assert_healthy();
}

/// A guest blocked in `wasi:io/poll` runs no wasm, so neither fuel nor the
/// epoch deadline can interrupt it. The host caps every clock pollable at
/// the request deadline and turns a cut-short sleep into a deadline trap.
#[test]
fn blocking_sleep_is_cut_at_the_deadline() {
    let e = env();
    // One hour requested; 60 ms timeout, fuel unlimited.
    let started = Instant::now();
    let inv = e.call("hostile-nofuel", "/sleep", "");
    let elapsed = started.elapsed();
    assert_eq!(trap_kind(&inv), TrapKind::DeadlineExceeded, "{inv:?}");
    assert_eq!(inv.outcome.http_status(), 504);
    assert!(elapsed >= Duration::from_millis(60), "{elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(1000),
        "sleep not capped at the deadline: {elapsed:?}"
    );
    // Same with a fuel budget: sleeping burns almost no fuel, so fuel alone
    // would never stop it either.
    let inv = e.call("hostile", "/sleep", "ms=600000");
    assert_eq!(trap_kind(&inv), TrapKind::DeadlineExceeded, "{inv:?}");
    assert!(inv.stats.total < Duration::from_secs(4), "{:?}", inv.stats);
    assert!(inv.stats.fuel_consumed < 100_000_000);
    assert_eq!(
        e.reg
            .runtime()
            .metrics()
            .traps
            .get(&["hostile-nofuel", "deadline-exceeded"]),
        1
    );
    e.assert_healthy();
}

#[test]
fn short_sleep_under_the_deadline_succeeds() {
    let e = env();
    let inv = e.call("hostile", "/sleep", "ms=20");
    match &inv.outcome {
        Outcome::Response(r) => {
            assert_eq!(r.status, 200);
            assert!(body(r).starts_with("slept "), "{}", body(r));
        }
        other => panic!("a sleep under the deadline must succeed: {other:?}"),
    }
    assert!(inv.stats.total >= Duration::from_millis(20));
}

/// Concurrent sleepers cannot hold invocation threads past their deadline,
/// so they cannot starve a well-behaved plugin.
#[test]
fn concurrent_sleepers_release_their_threads_at_the_deadline() {
    let e = Arc::new(env());
    let started = Instant::now();
    let sleepers: Vec<_> = (0..16)
        .map(|_| {
            let e = e.clone();
            std::thread::spawn(move || trap_kind(&e.call("hostile-nofuel", "/sleep", "")))
        })
        .collect();
    for s in sleepers {
        assert_eq!(s.join().unwrap(), TrapKind::DeadlineExceeded);
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    e.assert_healthy();
}
