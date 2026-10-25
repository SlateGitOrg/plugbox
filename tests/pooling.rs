//! Instance pooling and the ahead-of-time cache.

mod common;

use std::time::Duration;

use common::*;
use plugbox::Outcome;
use plugbox::config::InstanceStrategy;
use plugbox::engine::EngineSettings;

fn cfg() -> String {
    format!(
        "[[plugins]]\nname = \"h\"\nroute = \"/\"\ncomponent = {}\nlimits = {{ fuel = 0, timeout_ms = 2000 }}\n",
        lit(&wasm("hostile"))
    )
}

#[test]
fn exhausted_pool_sheds_instead_of_blocking() {
    let dir = TempDir::new("pool");
    let rt = runtime_with(
        EngineSettings {
            pool_size: 1,
            ..EngineSettings::default()
        },
        None,
    );
    let reg = registry(&dir, rt, &cfg());
    let busy = {
        let reg = reg.clone();
        std::thread::spawn(move || {
            let p = reg.snapshot().get("h").unwrap();
            reg.runtime().invoke(&p, &request("GET", "/spin", "ms=400"))
        })
    };
    std::thread::sleep(Duration::from_millis(100));
    let p = reg.snapshot().get("h").unwrap();
    let inv = reg.runtime().invoke(&p, &request("GET", "/spin", "ms=1"));
    assert!(
        matches!(inv.outcome, Outcome::Overloaded(_)),
        "{:?}",
        inv.outcome
    );
    assert_eq!(inv.outcome.http_status(), 503);
    assert!(matches!(busy.join().unwrap().outcome, Outcome::Response(_)));
    // The slot is free again.
    assert!(matches!(
        reg.runtime()
            .invoke(&p, &request("GET", "/spin", "ms=1"))
            .outcome,
        Outcome::Response(_)
    ));
    assert_eq!(reg.runtime().metrics().shed.get(&["pool_exhausted"]), 1);
}

#[test]
fn instances_never_share_state_between_requests() {
    let dir = TempDir::new("pool-state");
    let reg = registry(&dir, runtime(), &cfg());
    let p = reg.snapshot().get("h").unwrap();
    // The bomb fills memory with 0xA5 then traps; the next instance in the
    // same slot must start from the pristine image and run normally.
    let _ = reg.runtime().invoke(&p, &request("GET", "/bomb", ""));
    let inv = reg
        .runtime()
        .invoke(&p, &request("GET", "/huge-response", "bytes=64"));
    match inv.outcome {
        Outcome::Response(r) => assert_eq!(r.body, vec![b'z'; 64]),
        other => panic!("{other:?}"),
    }
    assert!(
        inv.stats.memory_peak < 4 << 20,
        "fresh instance, small heap: {}",
        inv.stats.memory_peak
    );
}

#[test]
fn on_demand_strategy_behaves_the_same() {
    let dir = TempDir::new("ondemand");
    let rt = runtime_with(
        EngineSettings {
            strategy: InstanceStrategy::OnDemand,
            ..EngineSettings::default()
        },
        None,
    );
    assert_eq!(rt.pool_live_instances(), None);
    let reg = registry(&dir, rt, &cfg());
    let p = reg.snapshot().get("h").unwrap();
    assert!(matches!(
        reg.runtime()
            .invoke(&p, &request("GET", "/spin", "ms=1"))
            .outcome,
        Outcome::Response(_)
    ));
    assert!(matches!(
        reg.runtime()
            .invoke(&p, &request("GET", "/bomb", ""))
            .outcome,
        Outcome::Trap {
            kind: plugbox::TrapKind::MemoryLimit,
            ..
        }
    ));
}

#[test]
fn aot_cache_is_written_and_reused() {
    let dir = TempDir::new("aot");
    let cache = dir.path("cache");
    let settings = EngineSettings::default();
    let first = runtime_with(settings.clone(), Some(cache.clone()));
    let a = first.compile_file("hello", &wasm("hello")).unwrap();
    assert!(!a.from_cache);
    let entries: Vec<_> = std::fs::read_dir(&cache).unwrap().collect();
    assert_eq!(entries.len(), 1);
    let second = runtime_with(settings, Some(cache.clone()));
    let b = second.compile_file("hello", &wasm("hello")).unwrap();
    assert!(b.from_cache, "second runtime must load the artifact");
    assert_eq!(a.sha256, b.sha256);
    // A corrupted artifact is discarded and rebuilt, not trusted.
    let entry = std::fs::read_dir(&cache)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::write(&entry, b"corrupt").unwrap();
    let third = runtime_with(EngineSettings::default(), Some(cache));
    let c = third.compile_file("hello", &wasm("hello")).unwrap();
    assert!(!c.from_cache);
    let reg_dir = TempDir::new("aot-reg");
    let reg = registry(
        &reg_dir,
        third,
        &format!(
            "[[plugins]]\nname = \"hello\"\nroute = \"/\"\ncomponent = {}\n",
            lit(&wasm("hello"))
        ),
    );
    let p = reg.snapshot().get("hello").unwrap();
    assert!(matches!(
        reg.runtime().invoke(&p, &request("GET", "/", "")).outcome,
        Outcome::Response(_)
    ));
}
