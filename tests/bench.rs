//! The benchmark harness runs every mode end to end (tiny sample counts —
//! this checks correctness, not speed).

mod common;

use common::*;
use plugbox::bench::{BenchOptions, Mode, render_table, run, run_mode};

#[test]
fn every_mode_produces_sane_numbers() {
    let scratch = TempDir::new("bench");
    let opts = BenchOptions {
        component: wasm("hello"),
        iterations: 20,
        cold_divisor: 4,
        threads: 2,
        scratch: scratch.0.clone(),
        path: "/".into(),
    };
    let results = run(&opts).unwrap();
    assert_eq!(results.len(), 4);
    for r in &results {
        assert!(r.p50_us > 0.0 && r.p50_us <= r.p90_us && r.p90_us <= r.p99_us, "{r:?}");
        assert!(r.p99_us <= r.max_us && r.throughput_rps > 0.0, "{r:?}");
    }
    assert_eq!(results[0].samples, 5);
    assert_eq!(results[3].samples, 20);
    assert!(results[3].instantiate_p50_us > 0.0);
    assert_eq!(results[0].instantiate_p50_us, 0.0);
    assert!(!scratch.path("aot-cache").exists(), "AOT scratch is cleaned up");
    let table = render_table(&results);
    assert_eq!(table.lines().count(), 6);
}

#[test]
fn failing_requests_fail_the_benchmark() {
    let scratch = TempDir::new("bench-fail");
    let opts = BenchOptions {
        component: wasm("hello"),
        iterations: 5,
        cold_divisor: 1,
        threads: 1,
        scratch: scratch.0.clone(),
        path: "/does-not-exist".into(),
    };
    assert!(run_mode(Mode::WarmPooled, &opts).is_err());
    let missing = BenchOptions {
        component: scratch.path("missing.wasm"),
        ..opts
    };
    assert!(run_mode(Mode::WarmOnDemand, &missing).is_err());
}
