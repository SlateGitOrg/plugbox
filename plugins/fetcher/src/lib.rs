//! `fetcher` — an edge proxy that calls an upstream through the host's
//! allow-listed outbound HTTP capability.
//!
//! * `GET /proxy/<rest>`   fetches `$UPSTREAM/<rest>` and relays the response.
//! * `GET /fetch?url=<u>`  fetches an arbitrary URL — the host allow-list
//!   decides whether that is permitted.

use plugbox_sdk::outbound_http::{self, HttpError, OutboundRequest};
use plugbox_sdk::{Guest, Request, Response, env, text};

struct Fetcher;

fn fetch(url: String) -> Response {
    let req = OutboundRequest {
        method: "GET".to_string(),
        url,
        headers: vec![("accept".to_string(), "*/*".to_string())],
        body: Vec::new(),
    };
    match outbound_http::fetch(&req) {
        Ok(resp) => {
            let mut headers: Vec<(String, String)> = resp
                .headers
                .into_iter()
                .filter(|(k, _)| k == "content-type")
                .collect();
            headers.push(("x-via".to_string(), "plugbox-fetcher".to_string()));
            Response { status: resp.status, headers, body: resp.body }
        }
        Err(err) => {
            let (status, msg) = match err {
                HttpError::NotGranted => (403, "outbound http not granted".to_string()),
                HttpError::Forbidden(m) => (403, format!("forbidden by allow-list: {m}")),
                HttpError::InvalidUrl(m) => (400, format!("invalid url: {m}")),
                HttpError::QuotaExceeded => (429, "outbound call budget exhausted".to_string()),
                HttpError::Timeout => (504, "upstream timeout".to_string()),
                HttpError::Transport(m) => (502, format!("upstream error: {m}")),
                HttpError::TooLarge => (502, "upstream response too large".to_string()),
            };
            text(status, format!("{msg}\n"))
        }
    }
}

impl Guest for Fetcher {
    fn handle(req: Request) -> Response {
        if let Some(rest) = req.path.strip_prefix("/proxy/") {
            let Some(base) = env::get("UPSTREAM") else {
                return text(500, "UPSTREAM is not configured\n");
            };
            let mut url = format!("{}/{rest}", base.trim_end_matches('/'));
            if !req.query.is_empty() {
                url.push('?');
                url.push_str(&req.query);
            }
            return fetch(url);
        }
        if req.path == "/fetch" {
            return match plugbox_sdk::query_param(&req.query, "url") {
                Some(url) => fetch(url),
                None => text(400, "missing ?url=\n"),
            };
        }
        text(404, "try /proxy/<path> or /fetch?url=<url>\n")
    }
}

plugbox_sdk::export!(Fetcher with_types_in plugbox_sdk::bindings);
