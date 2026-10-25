//! The import policy rejects components that ask for host interfaces the
//! sandbox does not provide, before any guest code runs.

mod common;

use common::*;
use plugbox::{Error, Registry};

#[test]
fn raw_socket_plugin_is_rejected_at_load_time() {
    let rt = runtime();
    let err = rt.compile_file("sneaky", &wasm("sneaky")).unwrap_err();
    let Error::Policy { plugin, violations } = err else {
        panic!("expected a policy error, got {err:?}")
    };
    assert_eq!(plugin, "sneaky");
    assert!(violations.iter().any(|v| v.contains("wasi:sockets/tcp")), "{violations:?}");
    assert!(violations.iter().all(|v| v.contains("wasi:sockets")), "{violations:?}");
}

#[test]
fn registry_refuses_to_start_with_a_rejected_plugin() {
    let dir = TempDir::new("policy");
    let path = dir.path("plugbox.toml");
    std::fs::write(
        &path,
        format!(
            "[[plugins]]\nname = \"sneaky\"\nroute = \"/\"\ncomponent = {}\n",
            lit(&wasm("sneaky"))
        ),
    )
    .unwrap();
    let err = Registry::load(runtime(), &path).unwrap_err();
    assert!(err.to_string().contains("violates the import policy"), "{err}");
}

#[test]
fn sample_plugins_pass_the_policy() {
    let rt = runtime();
    for name in ["hello", "counter", "fetcher", "hostile"] {
        let c = rt.compile_file(name, &wasm(name)).unwrap();
        assert!(c.report.is_allowed());
        assert!(c.report.exports.iter().any(|e| e.starts_with("plugbox:host/handler@0.1.")));
        assert!(!c.report.imports.iter().any(|i| i.starts_with("wasi:sockets")), "{name}");
    }
}

#[test]
fn a_component_without_the_handler_export_is_rejected() {
    let rt = runtime();
    let err = rt.compile("empty", b"(component)").unwrap_err();
    assert!(err.to_string().contains("violates the import policy"), "{err}");
}
