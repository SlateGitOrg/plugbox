//! Error types for configuration, loading and reloading plugins.
//!
//! Per-request failures are not errors in this sense: they are reported as
//! [`crate::invoke::Outcome`] values so the data plane can map them to HTTP
//! responses and metrics without unwinding.

use std::path::PathBuf;

/// Everything that can go wrong outside the per-request path.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The configuration file could not be read.
    #[error("cannot read config {path}: {source}")]
    ConfigIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The configuration file is not valid TOML or does not match the schema.
    #[error("invalid config {path}: {message}")]
    ConfigParse { path: PathBuf, message: String },
    /// The configuration parsed but is semantically invalid.
    #[error("invalid config: {0}")]
    ConfigInvalid(String),
    /// A component file could not be read.
    #[error("cannot read component {path}: {source}")]
    ComponentIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Wasmtime rejected the component (bad binary, compile error, link error).
    #[error("plugin `{plugin}`: {message}")]
    Component { plugin: String, message: String },
    /// The component imports something the sandbox does not provide.
    #[error("plugin `{plugin}` violates the import policy: {violations:?}")]
    Policy {
        plugin: String,
        violations: Vec<String>,
    },
    /// The wasmtime engine could not be created.
    #[error("engine setup failed: {0}")]
    Engine(String),
    /// Binding a listener or another I/O failure in the server.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Wrap a wasmtime error that happened while handling `plugin`.
    pub(crate) fn component(plugin: &str, err: &wasmtime::Error) -> Self {
        Error::Component {
            plugin: plugin.to_string(),
            message: format!("{err:#}"),
        }
    }
}

/// Crate-wide result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;
