//! Guest-side SDK for plugbox plugins.
//!
//! Re-exports the `wit-bindgen` bindings for the `plugbox:host/plugin` world
//! plus a handful of small helpers that every handler needs (building
//! responses, reading query parameters, escaping JSON). Plugins implement
//! [`Guest`] and register it with [`export!`]:
//!
//! ```ignore
//! struct Hello;
//! impl plugbox_sdk::Guest for Hello {
//!     fn handle(req: plugbox_sdk::Request) -> plugbox_sdk::Response {
//!         plugbox_sdk::text(200, "hello")
//!     }
//! }
//! plugbox_sdk::export!(Hello with_types_in plugbox_sdk::bindings);
//! ```

/// Generated bindings for the `plugin` world.
pub mod bindings {
    wit_bindgen::generate!({
        world: "plugin",
        path: "../../wit",
        pub_export_macro: true,
        default_bindings_module: "plugbox_sdk::bindings",
    });
}

pub use bindings::export;
pub use bindings::exports::plugbox::host::handler::Guest;
pub use bindings::plugbox::host::types::{Request, Response};
pub use bindings::plugbox::host::{env, kv, log, outbound_http};

/// Build a response with a `content-type` header.
pub fn respond(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Response {
    Response {
        status,
        headers: vec![("content-type".to_string(), content_type.to_string())],
        body: body.into(),
    }
}

/// Plain-text response.
pub fn text(status: u16, body: impl Into<String>) -> Response {
    respond(
        status,
        "text/plain; charset=utf-8",
        body.into().into_bytes(),
    )
}

/// JSON response; `body` must already be valid JSON.
pub fn json(status: u16, body: impl Into<String>) -> Response {
    respond(status, "application/json", body.into().into_bytes())
}

/// Look up a query parameter (first occurrence, `+` and `%XX` decoded).
pub fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (percent_decode(k) == name).then(|| percent_decode(v))
    })
}

/// Decode `application/x-www-form-urlencoded` escapes. Invalid escapes are
/// kept verbatim.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Quote and escape a string as a JSON string literal.
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Header lookup (names are lower-cased by the host).
pub fn header<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}
