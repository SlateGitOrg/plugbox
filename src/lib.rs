//! # plugbox
//!
//! A sandboxed WebAssembly plugin runtime for edge request handlers, built on
//! wasmtime and the component model.
//!
//! Plugins are WebAssembly components targeting the `plugbox:host/plugin`
//! world (`wit/plugbox.wit`). Each request runs in a fresh instance drawn
//! from wasmtime's pooling allocator, under three independent limits (fuel,
//! an epoch wall-clock deadline, a memory budget), with capabilities (env,
//! outbound HTTP, KV) granted per plugin by the operator.
//!
//! Module map:
//!
//! | module | role |
//! |---|---|
//! | [`config`] | `plugbox.toml` schema and validation |
//! | [`allowlist`] | strict URL parsing, allow rules, address policy |
//! | [`capability`] | resolved grants; [`capability::kv`] store |
//! | [`outbound`] | outbound-HTTP enforcement point and HTTP/1.1 client |
//! | [`engine`] | wasmtime engine configuration, epoch ticker |
//! | [`limits`] | per-instance memory limiter |
//! | [`clock`] | deadline-capped `wasi:clocks/monotonic-clock` |
//! | [`policy`] | load-time import policy |
//! | [`host`] | WIT bindings and host-function implementations |
//! | [`runtime`] | compile, bind, invoke, classify outcomes |
//! | [`registry`] | route table snapshots and hot reload |
//! | [`server`] | hyper data plane and admin plane |
//! | [`metrics`] | Prometheus registry |
//! | [`bench`] | cold vs pooled instantiation benchmark |

pub mod allowlist;
pub mod bench;
pub mod capability;
pub mod clock;
pub mod config;
pub mod engine;
pub mod error;
pub mod host;
pub mod limits;
pub mod metrics;
pub mod outbound;
pub mod policy;
pub mod registry;
pub mod runtime;
pub mod server;
pub mod stdio;

pub use config::Config;
pub use error::{Error, Result};
pub use host::{Request, Response};
pub use registry::Registry;
pub use runtime::{Invocation, LoadedPlugin, Outcome, Runtime, RuntimeOptions, TrapKind};
