//! Load-time import policy.
//!
//! Before a component is linked, every import it declares is checked against
//! an allow-list of interfaces the sandbox is willing to provide. This turns
//! "the plugin tried to open a raw socket at request time" into "the plugin
//! was rejected at deploy time, with a list of offending imports".
//!
//! Allowed:
//! * `plugbox:host/*` — the capability interfaces (each still gated by grants).
//! * `wasi:io`, `wasi:clocks`, `wasi:random`, `wasi:cli` — needed by any
//!   `wasm32-wasip2` program; the CLI world is inert (no args, empty env,
//!   stdout/stderr captured, stdin empty).
//! * `wasi:filesystem` — linked but inert: no directories are preopened, so
//!   every path operation fails.
//!
//! Everything else — notably `wasi:sockets` and `wasi:http` — is refused.

use wasmtime::Engine;
use wasmtime::component::Component;

/// Package/interface prefixes (without version) a component may import.
pub const ALLOWED_IMPORTS: &[&str] = &[
    "plugbox:host/",
    "wasi:io/",
    "wasi:clocks/",
    "wasi:random/",
    "wasi:cli/",
    "wasi:filesystem/",
];

/// The export every plugin must provide (any 0.1.x version).
pub const REQUIRED_EXPORT: &str = "plugbox:host/handler@0.1.";

/// What a component imports and exports, and whether that is acceptable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportReport {
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub violations: Vec<String>,
}

impl ImportReport {
    /// True when the component may be loaded.
    pub fn is_allowed(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Check import/export names against the policy.
pub fn evaluate(imports: Vec<String>, exports: Vec<String>) -> ImportReport {
    let mut violations: Vec<String> = imports
        .iter()
        .filter(|name| !ALLOWED_IMPORTS.iter().any(|p| name.starts_with(p)))
        .map(|name| format!("import `{name}` is not provided by the plugbox sandbox"))
        .collect();
    if !exports.iter().any(|e| e.starts_with(REQUIRED_EXPORT)) {
        violations.push(format!(
            "component does not export `{REQUIRED_EXPORT}x` (was it built against wit/plugbox.wit?)"
        ));
    }
    ImportReport {
        imports,
        exports,
        violations,
    }
}

/// Inspect a compiled component.
pub fn inspect(engine: &Engine, component: &Component) -> ImportReport {
    let ty = component.component_type();
    let imports = ty.imports(engine).map(|(n, _)| n.to_string()).collect();
    let exports = ty.exports(engine).map(|(n, _)| n.to_string()).collect();
    evaluate(imports, exports)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn accepts_typical_wasip2_plugin() {
        let r = evaluate(
            s(&[
                "plugbox:host/kv@0.1.0",
                "wasi:io/streams@0.2.6",
                "wasi:cli/environment@0.2.6",
                "wasi:filesystem/preopens@0.2.6",
            ]),
            s(&["plugbox:host/handler@0.1.0"]),
        );
        assert!(r.is_allowed(), "{:?}", r.violations);
    }

    #[test]
    fn rejects_sockets_http_and_missing_export() {
        let r = evaluate(
            s(&[
                "wasi:sockets/tcp@0.2.6",
                "wasi:http/outgoing-handler@0.2.6",
                "evil:x/y",
            ]),
            s(&["wasi:cli/run@0.2.6"]),
        );
        assert!(!r.is_allowed());
        assert_eq!(r.violations.len(), 4, "{:?}", r.violations);
        assert!(r.violations[0].contains("wasi:sockets/tcp"));
        assert!(r.violations[3].contains("does not export"));
    }

    #[test]
    fn inspects_a_real_component() {
        let engine = Engine::default();
        let wat = r#"(component
            (import "wasi:sockets/tcp@0.2.0" (instance))
        )"#;
        let c = Component::new(&engine, wat).unwrap();
        let r = inspect(&engine, &c);
        assert_eq!(r.imports, ["wasi:sockets/tcp@0.2.0"]);
        assert!(r.exports.is_empty());
        assert_eq!(r.violations.len(), 2);
    }
}
