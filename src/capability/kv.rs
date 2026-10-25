//! The host-side key-value store behind the `kv` capability.
//!
//! One in-process store serves every plugin; data is partitioned by
//! namespace, and a plugin can only reach the namespace named in its grant.
//! The store lives in the runtime (not in a plugin instance), so it survives
//! per-request instance teardown and hot reloads.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use crate::config::KvMode;

/// Longest accepted key, in bytes.
pub const MAX_KEY_LEN: usize = 512;

/// Host-side KV failures (mirrors the WIT `kv-error` variant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvError {
    NotGranted,
    ReadOnly,
    QuotaExceeded(String),
    InvalidKey(String),
    NotANumber,
}

/// The resolved KV grant of one plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvGrantSpec {
    pub namespace: String,
    pub mode: KvMode,
    pub max_keys: usize,
    pub max_value: usize,
}

/// Namespaced in-memory store.
#[derive(Debug, Default)]
pub struct KvStore {
    namespaces: Mutex<HashMap<String, BTreeMap<String, Vec<u8>>>>,
}

fn check_key(key: &str) -> Result<(), KvError> {
    if key.is_empty() {
        return Err(KvError::InvalidKey("empty key".into()));
    }
    if key.len() > MAX_KEY_LEN {
        return Err(KvError::InvalidKey(format!("key longer than {MAX_KEY_LEN} bytes")));
    }
    if key.chars().any(char::is_control) {
        return Err(KvError::InvalidKey("control characters in key".into()));
    }
    Ok(())
}

fn writable(grant: &KvGrantSpec) -> Result<(), KvError> {
    match grant.mode {
        KvMode::ReadWrite => Ok(()),
        KvMode::ReadOnly => Err(KvError::ReadOnly),
    }
}

impl KvStore {
    /// An empty store.
    pub fn new() -> KvStore {
        KvStore::default()
    }

    fn with_ns<R>(&self, ns: &str, f: impl FnOnce(&mut BTreeMap<String, Vec<u8>>) -> R) -> R {
        let mut guard = self
            .namespaces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(guard.entry(ns.to_string()).or_default())
    }

    /// Read a value.
    pub fn get(&self, grant: &KvGrantSpec, key: &str) -> Result<Option<Vec<u8>>, KvError> {
        check_key(key)?;
        Ok(self.with_ns(&grant.namespace, |m| m.get(key).cloned()))
    }

    /// Insert or replace a value, enforcing the value-size and key-count quotas.
    pub fn set(&self, grant: &KvGrantSpec, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        writable(grant)?;
        check_key(key)?;
        if value.len() > grant.max_value {
            return Err(KvError::QuotaExceeded(format!(
                "value is {} bytes, limit is {}",
                value.len(),
                grant.max_value
            )));
        }
        self.with_ns(&grant.namespace, |m| {
            if !m.contains_key(key) && m.len() >= grant.max_keys {
                return Err(KvError::QuotaExceeded(format!(
                    "namespace holds the maximum of {} keys",
                    grant.max_keys
                )));
            }
            m.insert(key.to_string(), value);
            Ok(())
        })
    }

    /// Remove a key; returns whether it existed.
    pub fn delete(&self, grant: &KvGrantSpec, key: &str) -> Result<bool, KvError> {
        writable(grant)?;
        check_key(key)?;
        Ok(self.with_ns(&grant.namespace, |m| m.remove(key).is_some()))
    }

    /// Sorted keys starting with `prefix`, at most `limit`.
    pub fn list_keys(&self, grant: &KvGrantSpec, prefix: &str, limit: u32) -> Vec<String> {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        self.with_ns(&grant.namespace, |m| {
            m.range(prefix.to_string()..)
                .take_while(|(k, _)| k.starts_with(prefix))
                .take(limit)
                .map(|(k, _)| k.clone())
                .collect()
        })
    }

    /// Atomically add `delta` to a decimal integer (missing = 0).
    pub fn increment(&self, grant: &KvGrantSpec, key: &str, delta: i64) -> Result<i64, KvError> {
        writable(grant)?;
        check_key(key)?;
        self.with_ns(&grant.namespace, |m| {
            let current = match m.get(key) {
                Some(v) => std::str::from_utf8(v)
                    .ok()
                    .and_then(|s| s.trim().parse::<i64>().ok())
                    .ok_or(KvError::NotANumber)?,
                None => {
                    if m.len() >= grant.max_keys {
                        return Err(KvError::QuotaExceeded(format!(
                            "namespace holds the maximum of {} keys",
                            grant.max_keys
                        )));
                    }
                    0
                }
            };
            let next = current
                .checked_add(delta)
                .ok_or_else(|| KvError::QuotaExceeded("integer overflow".into()))?;
            m.insert(key.to_string(), next.to_string().into_bytes());
            Ok(next)
        })
    }

    /// `(keys, value bytes)` held in a namespace.
    pub fn usage(&self, namespace: &str) -> (usize, usize) {
        self.with_ns(namespace, |m| (m.len(), m.values().map(Vec::len).sum()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn grant(ns: &str) -> KvGrantSpec {
        KvGrantSpec {
            namespace: ns.into(),
            mode: KvMode::ReadWrite,
            max_keys: 3,
            max_value: 8,
        }
    }

    #[test]
    fn crud_and_namespaces_are_isolated() {
        let kv = KvStore::new();
        let a = grant("a");
        let b = grant("b");
        kv.set(&a, "k", b"v1".to_vec()).unwrap();
        assert_eq!(kv.get(&a, "k").unwrap(), Some(b"v1".to_vec()));
        assert_eq!(kv.get(&b, "k").unwrap(), None, "namespaces must not leak");
        assert!(kv.delete(&a, "k").unwrap());
        assert!(!kv.delete(&a, "k").unwrap());
        assert_eq!(kv.usage("a"), (0, 0));
    }

    #[test]
    fn quotas_and_validation() {
        let kv = KvStore::new();
        let g = grant("q");
        assert!(matches!(
            kv.set(&g, "big", vec![0; 9]),
            Err(KvError::QuotaExceeded(_))
        ));
        for k in ["a", "b", "c"] {
            kv.set(&g, k, b"1".to_vec()).unwrap();
        }
        assert!(matches!(kv.set(&g, "d", b"1".to_vec()), Err(KvError::QuotaExceeded(_))));
        assert!(matches!(kv.increment(&g, "d", 1), Err(KvError::QuotaExceeded(_))));
        kv.set(&g, "a", b"22".to_vec()).unwrap(); // overwrite is fine at the cap
        assert_eq!(kv.usage("q"), (3, 4));
        assert!(matches!(kv.get(&g, ""), Err(KvError::InvalidKey(_))));
        assert!(matches!(kv.get(&g, "a\nb"), Err(KvError::InvalidKey(_))));
        assert!(matches!(
            kv.get(&g, &"x".repeat(MAX_KEY_LEN + 1)),
            Err(KvError::InvalidKey(_))
        ));
    }

    #[test]
    fn read_only_grants_refuse_writes() {
        let kv = KvStore::new();
        let rw = grant("shared");
        let ro = KvGrantSpec {
            mode: KvMode::ReadOnly,
            ..grant("shared")
        };
        kv.set(&rw, "k", b"v".to_vec()).unwrap();
        assert_eq!(kv.get(&ro, "k").unwrap(), Some(b"v".to_vec()));
        assert_eq!(kv.set(&ro, "k", vec![]), Err(KvError::ReadOnly));
        assert_eq!(kv.delete(&ro, "k"), Err(KvError::ReadOnly));
        assert_eq!(kv.increment(&ro, "k", 1), Err(KvError::ReadOnly));
    }

    #[test]
    fn increment_semantics() {
        let kv = KvStore::new();
        let g = KvGrantSpec {
            max_value: 64,
            ..grant("n")
        };
        assert_eq!(kv.increment(&g, "c", 5).unwrap(), 5);
        assert_eq!(kv.increment(&g, "c", -7).unwrap(), -2);
        kv.set(&g, "s", b"abc".to_vec()).unwrap();
        assert_eq!(kv.increment(&g, "s", 1), Err(KvError::NotANumber));
        kv.set(&g, "m", i64::MAX.to_string().into_bytes()).unwrap();
        assert!(matches!(kv.increment(&g, "m", 1), Err(KvError::QuotaExceeded(_))));
    }

    #[test]
    fn list_keys_is_sorted_prefixed_and_limited() {
        let kv = KvStore::new();
        let g = KvGrantSpec {
            max_keys: 100,
            ..grant("l")
        };
        for k in ["hit:b", "hit:a", "miss", "hit:c", "hi"] {
            kv.set(&g, k, vec![]).unwrap();
        }
        assert_eq!(kv.list_keys(&g, "hit:", 10), ["hit:a", "hit:b", "hit:c"]);
        assert_eq!(kv.list_keys(&g, "hit:", 2), ["hit:a", "hit:b"]);
        assert_eq!(kv.list_keys(&g, "", 100).len(), 5);
        assert!(kv.list_keys(&g, "zzz", 10).is_empty());
    }

    #[test]
    fn concurrent_increments_are_atomic() {
        let kv = std::sync::Arc::new(KvStore::new());
        let g = KvGrantSpec {
            max_value: 64,
            ..grant("atomic")
        };
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let kv = kv.clone();
                let g = g.clone();
                std::thread::spawn(move || {
                    for _ in 0..500 {
                        kv.increment(&g, "n", 1).unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(kv.get(&g, "n").unwrap(), Some(b"4000".to_vec()));
    }

    proptest! {
        #[test]
        fn store_matches_a_model(ops in proptest::collection::vec((0u8..3, 0u8..5, 0u8..9), 0..60)) {
            let kv = KvStore::new();
            let g = KvGrantSpec { namespace: "p".into(), mode: KvMode::ReadWrite, max_keys: 4, max_value: 6 };
            let mut model: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            for (op, k, len) in ops {
                let key = format!("k{k}");
                match op {
                    0 => {
                        let v = vec![b'x'; len as usize];
                        let want_ok = v.len() <= 6 && (model.contains_key(&key) || model.len() < 4);
                        prop_assert_eq!(kv.set(&g, &key, v.clone()).is_ok(), want_ok);
                        if want_ok { model.insert(key, v); }
                    }
                    1 => prop_assert_eq!(kv.delete(&g, &key).unwrap(), model.remove(&key).is_some()),
                    _ => prop_assert_eq!(kv.get(&g, &key).unwrap(), model.get(&key).cloned()),
                }
            }
            let keys: Vec<String> = model.keys().cloned().collect();
            prop_assert_eq!(kv.list_keys(&g, "", 100), keys);
        }
    }
}
