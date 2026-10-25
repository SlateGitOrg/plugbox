//! `hello` — the smallest useful plugin.
//!
//! * `GET /`        greets using the granted `GREETING` variable.
//! * `GET /env`     lists the env names this plugin was granted.
//! * `POST /echo`   echoes method, path, query, headers and body as JSON.

use plugbox_sdk::{Guest, Request, Response, env, json, json_str, log, text};

struct Hello;

impl Guest for Hello {
    fn handle(req: Request) -> Response {
        log::log(log::Level::Debug, &format!("{} {}", req.method, req.path));
        match req.path.as_str() {
            "/" => {
                let greeting = env::get("GREETING").unwrap_or_else(|| "hello".to_string());
                let name = plugbox_sdk::query_param(&req.query, "name")
                    .unwrap_or_else(|| "world".to_string());
                text(200, format!("{greeting}, {name}!\n"))
            }
            "/env" => {
                let names: Vec<String> = env::names().iter().map(|n| json_str(n)).collect();
                json(200, format!("{{\"granted\":[{}]}}", names.join(",")))
            }
            "/echo" => {
                let headers: Vec<String> = req
                    .headers
                    .iter()
                    .map(|(k, v)| format!("[{},{}]", json_str(k), json_str(v)))
                    .collect();
                let body = String::from_utf8_lossy(&req.body);
                json(
                    200,
                    format!(
                        "{{\"method\":{},\"path\":{},\"query\":{},\"headers\":[{}],\"body\":{}}}",
                        json_str(&req.method),
                        json_str(&req.path),
                        json_str(&req.query),
                        headers.join(","),
                        json_str(&body)
                    ),
                )
            }
            _ => text(404, "no such route\n"),
        }
    }
}

plugbox_sdk::export!(Hello with_types_in plugbox_sdk::bindings);
