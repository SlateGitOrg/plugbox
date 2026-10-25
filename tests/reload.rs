//! Hot reload: atomic swaps, all-or-nothing failures, in-flight requests on
//! the old version, and the polling watcher.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use plugbox::{Error, Outcome, Registry};

fn config(component: &std::path::Path, greeting: &str) -> String {
    format!(
        "[[plugins]]\nname = \"edge\"\nroute = \"/\"\ncomponent = {}\n\
         limits = {{ fuel = 0, timeout_ms = 2000 }}\n\
         [plugins.grants.env]\nvars = {{ GREETING = \"{greeting}\" }}\n\
         [plugins.grants.kv]\n",
        lit(component)
    )
}

fn greet(reg: &Registry) -> String {
    let p = reg.snapshot().get("edge").unwrap();
    match reg.runtime().invoke(&p, &request("GET", "/", "")).outcome {
        Outcome::Response(r) => body(&r),
        other => panic!("{other:?}"),
    }
}

fn setup() -> (TempDir, Arc<Registry>, std::path::PathBuf) {
    let dir = TempDir::new("reload");
    let component = dir.path("edge.wasm");
    std::fs::copy(wasm("hello"), &component).unwrap();
    let reg = registry(&dir, runtime(), &config(&component, "v1"));
    (dir, reg, component)
}

#[test]
fn config_change_rebinds_without_recompiling() {
    let (dir, reg, component) = setup();
    assert_eq!(greet(&reg), "v1, world!\n");
    let before = reg.snapshot().get("edge").unwrap();
    std::fs::write(dir.path("plugbox.toml"), config(&component, "v2")).unwrap();
    let report = reg.reload().unwrap();
    assert_eq!(report.generation, 2);
    assert_eq!(report.rebound, ["edge"]);
    assert!(report.updated.is_empty() && report.added.is_empty());
    let after = reg.snapshot().get("edge").unwrap();
    assert!(
        Arc::ptr_eq(&before.compiled, &after.compiled),
        "same bytes must not recompile"
    );
    assert_eq!(greet(&reg), "v2, world!\n");
    assert_eq!(reg.runtime().metrics().generation.get(), 2);
    // No change at all is still a successful, empty reload.
    let report = reg.reload().unwrap();
    assert_eq!(report.unchanged, ["edge"]);
}

#[test]
fn component_swap_updates_and_kv_survives() {
    let (_dir, reg, component) = setup();
    std::fs::copy(wasm("counter"), &component).unwrap();
    let report = reg.reload().unwrap();
    assert_eq!(report.updated, ["edge"]);
    let p = reg.snapshot().get("edge").unwrap();
    let hit = |reg: &Registry| match reg
        .runtime()
        .invoke(
            &reg.snapshot().get("edge").unwrap(),
            &request("POST", "/hit/x", ""),
        )
        .outcome
    {
        Outcome::Response(r) => body(&r),
        other => panic!("{other:?}"),
    };
    assert_eq!(hit(&reg), r#"{"name":"x","count":1}"#);
    // Reload again with identical bytes: KV state is runtime-owned and survives.
    std::fs::copy(wasm("counter"), &component).unwrap();
    reg.reload().unwrap();
    assert_eq!(hit(&reg), r#"{"name":"x","count":2}"#);
    assert_ne!(p.version(), "");
}

#[test]
fn failed_reload_keeps_serving_the_old_snapshot() {
    let (dir, reg, component) = setup();
    // 1. Garbage component bytes.
    std::fs::write(&component, b"\0asm garbage").unwrap();
    assert!(matches!(reg.reload(), Err(Error::Component { .. })));
    assert_eq!(reg.snapshot().generation, 1);
    assert_eq!(greet(&reg), "v1, world!\n");
    assert!(reg.last_error().unwrap().contains("edge"));
    // 2. A policy-violating component.
    std::fs::copy(wasm("sneaky"), &component).unwrap();
    assert!(matches!(reg.reload(), Err(Error::Policy { .. })));
    // 3. Invalid config.
    std::fs::write(dir.path("plugbox.toml"), "[[plugins]]\nname = 3\n").unwrap();
    assert!(matches!(reg.reload(), Err(Error::ConfigParse { .. })));
    // 4. Missing component file.
    std::fs::write(
        dir.path("plugbox.toml"),
        config(&dir.path("gone.wasm"), "v1"),
    )
    .unwrap();
    assert!(matches!(reg.reload(), Err(Error::ComponentIo { .. })));
    assert_eq!(greet(&reg), "v1, world!\n", "old version still serves");
    assert_eq!(reg.runtime().metrics().reloads.get(&["error"]), 4);
    // Recovery clears the error.
    std::fs::copy(wasm("hello"), &component).unwrap();
    std::fs::write(dir.path("plugbox.toml"), config(&component, "v3")).unwrap();
    reg.reload().unwrap();
    assert!(reg.last_error().is_none());
    assert_eq!(greet(&reg), "v3, world!\n");
}

#[test]
fn restart_only_settings_produce_warnings() {
    let (dir, reg, component) = setup();
    let text = format!(
        "[server]\nmax_concurrency = 3\n[runtime]\npool_size = 9\n{}",
        config(&component, "v1")
    );
    std::fs::write(dir.path("plugbox.toml"), text).unwrap();
    let report = reg.reload().unwrap();
    assert_eq!(report.warnings.len(), 2, "{:?}", report.warnings);
}

#[test]
fn plugins_can_be_added_and_removed() {
    let (dir, reg, component) = setup();
    let two = format!(
        "{}[[plugins]]\nname = \"count\"\nroute = \"/count\"\ncomponent = {}\n",
        config(&component, "v1"),
        lit(&wasm("counter"))
    );
    std::fs::write(dir.path("plugbox.toml"), &two).unwrap();
    let r = reg.reload().unwrap();
    assert_eq!(r.added, ["count"]);
    let snap = reg.snapshot();
    let (p, rest) = snap.route("/count/hit/a").unwrap();
    assert_eq!((&*p.name, rest.as_str()), ("count", "/hit/a"));
    let (p, _) = snap.route("/counter").unwrap();
    assert_eq!(&*p.name, "edge", "/counter is not under /count");
    std::fs::write(dir.path("plugbox.toml"), config(&component, "v1")).unwrap();
    assert_eq!(reg.reload().unwrap().removed, ["count"]);
    assert!(reg.snapshot().get("count").is_none());
}

#[test]
fn in_flight_requests_finish_on_the_old_version() {
    let dir = TempDir::new("reload-inflight");
    let component = dir.path("edge.wasm");
    std::fs::copy(wasm("hostile"), &component).unwrap();
    let reg = registry(&dir, runtime(), &config(&component, "v1"));
    let old = reg.snapshot().get("edge").unwrap();
    let worker = {
        let reg = reg.clone();
        std::thread::spawn(move || {
            let p = reg.snapshot().get("edge").unwrap();
            reg.runtime().invoke(&p, &request("GET", "/spin", "ms=300"))
        })
    };
    std::thread::sleep(Duration::from_millis(50));
    std::fs::copy(wasm("hello"), &component).unwrap();
    reg.reload().unwrap();
    let inv = worker.join().unwrap();
    assert!(
        matches!(&inv.outcome, Outcome::Response(r) if body(r).starts_with("spun 300ms")),
        "{:?}",
        inv.outcome
    );
    assert_ne!(reg.snapshot().get("edge").unwrap().version(), old.version());
    assert_eq!(greet(&reg), "v1, world!\n");
}

#[test]
fn watcher_reloads_changed_files() {
    let (dir, reg, component) = setup();
    let _watcher = reg.watch(Duration::from_millis(20));
    std::thread::sleep(Duration::from_millis(30));
    std::fs::write(dir.path("plugbox.toml"), config(&component, "watched")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while reg.snapshot().generation < 2 {
        assert!(Instant::now() < deadline, "watcher never reloaded");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(greet(&reg), "watched, world!\n");
    // A broken write is attempted once, then not retried until it changes.
    std::fs::write(&component, b"broken").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while reg.runtime().metrics().reloads.get(&["error"]) == 0 {
        assert!(
            Instant::now() < deadline,
            "watcher never tried the broken file"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(
        reg.runtime().metrics().reloads.get(&["error"]),
        1,
        "must not retry-loop"
    );
    assert_eq!(greet(&reg), "watched, world!\n");
}
