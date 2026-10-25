//! Capability grants, resolved from configuration into the form the host
//! functions check on every call.
//!
//! The design rule is *deny by default, deny without trapping*: a plugin
//! that calls an interface it was not granted gets a typed error (`none`,
//! `not-granted`, `forbidden`) back, the denial is counted in metrics, and the
//! request carries on. Traps are reserved for resource-limit violations.

pub mod kv;

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use crate::allowlist::{AddressPolicy, AllowList};
use crate::config::PluginConfig;
use kv::KvGrantSpec;

/// Capability names used in metrics labels and audit logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    Env,
    Http,
    Kv,
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Capability::Env => "env",
            Capability::Http => "http",
            Capability::Kv => "kv",
        })
    }
}

/// A resolved outbound-HTTP grant.
#[derive(Clone, Debug)]
pub struct HttpCapability {
    pub allow: AllowList,
    pub policy: AddressPolicy,
    /// Calls allowed per inbound request.
    pub max_requests: u32,
    /// Per-call timeout ceiling.
    pub timeout: Duration,
    /// Largest upstream body accepted.
    pub max_response: usize,
}

/// Everything one plugin is allowed to do.
#[derive(Clone, Debug, Default)]
pub struct Capabilities {
    /// The complete environment the plugin can observe.
    pub env: BTreeMap<String, String>,
    pub http: Option<HttpCapability>,
    pub kv: Option<KvGrantSpec>,
}

impl Capabilities {
    /// Resolve a plugin's grants. `host_env` looks up variables named in
    /// `grants.env.inherit`; names it cannot find are returned as warnings.
    pub fn resolve(
        cfg: &PluginConfig,
        host_env: impl Fn(&str) -> Option<String>,
    ) -> Result<(Capabilities, Vec<String>), String> {
        let mut warnings = Vec::new();
        let mut env = cfg.grants.env.vars.clone();
        for name in &cfg.grants.env.inherit {
            match host_env(name) {
                Some(v) => {
                    env.insert(name.clone(), v);
                }
                None => warnings.push(format!(
                    "env var `{name}` is granted via inherit but not set on the host"
                )),
            }
        }
        let http = match &cfg.grants.http {
            Some(h) => Some(HttpCapability {
                allow: AllowList::parse(&h.allow)?,
                policy: AddressPolicy {
                    allow_private: h.allow_private,
                },
                max_requests: h.max_requests,
                timeout: Duration::from_millis(h.timeout_ms),
                max_response: h.max_response.as_usize(),
            }),
            None => None,
        };
        let kv = cfg.grants.kv.as_ref().map(|k| KvGrantSpec {
            namespace: cfg.kv_namespace().unwrap_or(&cfg.name).to_string(),
            mode: k.mode,
            max_keys: k.max_keys,
            max_value: k.max_value.as_usize(),
        });
        Ok((Capabilities { env, http, kv }, warnings))
    }

    /// Short human summary, e.g. `env[GREETING] http[1 rule] kv[counter rw]`.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.env.is_empty() {
            let names: Vec<&str> = self.env.keys().map(String::as_str).collect();
            parts.push(format!("env[{}]", names.join(",")));
        }
        if let Some(h) = &self.http {
            parts.push(format!(
                "http[{} calls/req{}]",
                h.max_requests,
                if h.policy.allow_private {
                    ", private ok"
                } else {
                    ""
                }
            ));
        }
        if let Some(k) = &self.kv {
            let mode = match k.mode {
                crate::config::KvMode::ReadWrite => "rw",
                crate::config::KvMode::ReadOnly => "ro",
            };
            parts.push(format!("kv[{} {mode}]", k.namespace));
        }
        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join(" ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::Path;

    fn plugin(extra: &str) -> PluginConfig {
        let text =
            format!("[[plugins]]\nname = \"p\"\nroute = \"/p\"\ncomponent = \"p.wasm\"\n{extra}");
        Config::parse(&text, Path::new("."))
            .unwrap()
            .plugins
            .remove(0)
    }

    #[test]
    fn nothing_granted_by_default() {
        let (caps, warnings) = Capabilities::resolve(&plugin(""), |_| Some("leak".into())).unwrap();
        assert!(
            caps.env.is_empty(),
            "host env must never be inherited implicitly"
        );
        assert!(caps.http.is_none() && caps.kv.is_none());
        assert!(warnings.is_empty());
        assert_eq!(caps.summary(), "none");
    }

    #[test]
    fn resolves_every_grant() {
        let cfg = plugin(
            r#"
            [plugins.grants.env]
            vars = { A = "1" }
            inherit = ["HOME_REGION", "MISSING"]
            [plugins.grants.http]
            allow = ["http://127.0.0.1:1/*"]
            allow_private = true
            [plugins.grants.kv]
            mode = "read-only"
            "#,
        );
        let (caps, warnings) = Capabilities::resolve(&cfg, |n| {
            (n == "HOME_REGION").then(|| "eu-west".to_string())
        })
        .unwrap();
        assert_eq!(caps.env.get("A").map(String::as_str), Some("1"));
        assert_eq!(
            caps.env.get("HOME_REGION").map(String::as_str),
            Some("eu-west")
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("MISSING"));
        let http = caps.http.as_ref().unwrap();
        assert!(http.policy.allow_private);
        assert_eq!(http.max_requests, 8);
        assert_eq!(caps.kv.as_ref().unwrap().namespace, "p");
        assert_eq!(
            caps.summary(),
            "env[A,HOME_REGION] http[8 calls/req, private ok] kv[p ro]"
        );
        assert_eq!(Capability::Kv.to_string(), "kv");
        assert_eq!(Capability::Http.to_string(), "http");
        assert_eq!(Capability::Env.to_string(), "env");
    }
}
