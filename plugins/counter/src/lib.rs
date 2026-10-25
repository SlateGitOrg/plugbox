//! `counter` — a hit counter backed by the host KV capability.
//!
//! * `POST /hit/<name>`  atomically increments `<name>` and returns the count.
//! * `GET  /hit/<name>`  returns the current count (0 if unseen).
//! * `GET  /keys`        lists counter names (at most 100).
//! * `DELETE /hit/<name>` resets a counter.

use plugbox_sdk::{Guest, Request, Response, json, json_str, kv, text};

struct Counter;

fn kv_failure(err: kv::KvError) -> Response {
    let (status, msg) = match err {
        kv::KvError::NotGranted => (403, "kv not granted".to_string()),
        kv::KvError::ReadOnly => (403, "kv is read-only".to_string()),
        kv::KvError::QuotaExceeded(m) => (507, format!("quota: {m}")),
        kv::KvError::InvalidKey(m) => (400, format!("invalid key: {m}")),
        kv::KvError::NotANumber => (409, "stored value is not a number".to_string()),
    };
    text(status, format!("{msg}\n"))
}

impl Guest for Counter {
    fn handle(req: Request) -> Response {
        if req.path == "/keys" {
            return match kv::list_keys("hit:", 100) {
                Ok(keys) => {
                    let names: Vec<String> = keys
                        .iter()
                        .map(|k| json_str(k.trim_start_matches("hit:")))
                        .collect();
                    json(200, format!("{{\"counters\":[{}]}}", names.join(",")))
                }
                Err(e) => kv_failure(e),
            };
        }
        let Some(name) = req.path.strip_prefix("/hit/").filter(|n| !n.is_empty()) else {
            return text(404, "try POST /hit/<name>\n");
        };
        let key = format!("hit:{name}");
        let result = match req.method.as_str() {
            "POST" => kv::increment(&key, 1),
            "GET" => match kv::get(&key) {
                Ok(Some(v)) => Ok(String::from_utf8_lossy(&v).parse().unwrap_or(0)),
                Ok(None) => Ok(0),
                Err(e) => Err(e),
            },
            "DELETE" => kv::delete(&key).map(|_| 0),
            _ => return text(405, "method not allowed\n"),
        };
        match result {
            Ok(count) => json(
                200,
                format!("{{\"name\":{},\"count\":{count}}}", json_str(name)),
            ),
            Err(e) => kv_failure(e),
        }
    }
}

plugbox_sdk::export!(Counter with_types_in plugbox_sdk::bindings);
