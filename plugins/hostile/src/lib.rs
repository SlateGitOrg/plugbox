//! `hostile` — a deliberately misbehaving plugin used by the test-suite and
//! the demo to prove that every sandbox limit trips and that the host stays
//! healthy afterwards. It is benign: every "attack" targets the sandbox
//! itself, never a real system.
//!
//! | route            | misbehaviour                                   | expected host reaction            |
//! |------------------|------------------------------------------------|-----------------------------------|
//! | `/loop`          | infinite loop                                  | fuel or epoch deadline trap       |
//! | `/bomb`          | allocates until memory runs out                | memory limit trap                 |
//! | `/stack`         | recursion with stack arrays (shadow stack)     | memory-fault trap                 |
//! | `/recurse`       | recursion with register-only frames            | stack-overflow trap               |
//! | `/panic`         | `panic!`                                       | guest abort trap                  |
//! | `/forbidden`     | fetches the cloud metadata address             | `forbidden` error from allow-list |
//! | `/secret`        | reads env vars and files it was not granted    | `none` / WASI errors              |
//! | `/kv`            | writes KV without a grant                      | `not-granted` error               |
//! | `/fetch-flood`   | calls outbound HTTP until refused              | `quota-exceeded` error            |
//! | `/log-flood`     | logs 10 000 lines and floods stdout            | host truncates                    |
//! | `/huge-response` | returns a body larger than the response limit  | host replaces with 502            |
//! | `/spin?ms=N`     | busy-waits N milliseconds (wall clock)         | fine below the deadline           |
//! | `/sleep?ms=N`    | blocks in WASI poll (`thread::sleep`, 1 h)     | sleep cut at the deadline → 504   |

use std::hint::black_box;
use std::time::{Duration, Instant};

use plugbox_sdk::outbound_http::{self, HttpError, OutboundRequest};
use plugbox_sdk::{Guest, Request, Response, env, json, json_str, kv, log, query_param, text};

struct Hostile;

fn get(url: &str) -> Result<u16, HttpError> {
    let req = OutboundRequest {
        method: "GET".to_string(),
        url: url.to_string(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    outbound_http::fetch(&req).map(|r| r.status)
}

fn describe(err: &HttpError) -> String {
    match err {
        HttpError::NotGranted => "not-granted".to_string(),
        HttpError::Forbidden(m) => format!("forbidden: {m}"),
        HttpError::InvalidUrl(m) => format!("invalid-url: {m}"),
        HttpError::QuotaExceeded => "quota-exceeded".to_string(),
        HttpError::Timeout => "timeout".to_string(),
        HttpError::Transport(m) => format!("transport: {m}"),
        HttpError::TooLarge => "too-large".to_string(),
    }
}

/// Frames hold an address-taken array, so they live on Rust's *shadow*
/// stack inside linear memory. That stack has no guard page: overflowing it
/// walks the stack pointer below address 0, which wasm reports as an
/// out-of-bounds memory access.
#[allow(unconditional_recursion)]
fn recurse_shadow(depth: u64, pad: [u64; 16]) -> u64 {
    let pad = black_box(pad);
    recurse_shadow(depth + 1, pad) + pad[(depth % 16) as usize]
}

/// Frames are plain wasm locals, so only the engine's native wasm stack
/// grows; wasmtime's `max_wasm_stack` turns that into a stack-overflow trap.
fn recurse_native(depth: u64) -> u64 {
    if black_box(depth) == u64::MAX {
        return 0;
    }
    recurse_native(depth + 1).wrapping_add(black_box(1))
}

impl Guest for Hostile {
    fn handle(req: Request) -> Response {
        match req.path.as_str() {
            "/loop" => {
                let mut n: u64 = 0;
                loop {
                    n = black_box(n.wrapping_add(1));
                }
            }
            "/bomb" => {
                let mut hoard: Vec<Vec<u8>> = Vec::new();
                loop {
                    // Touch every page so the memory is really committed.
                    let chunk = vec![0xA5u8; 1 << 20];
                    hoard.push(black_box(chunk));
                }
            }
            "/stack" => {
                let depth = recurse_shadow(0, [7; 16]);
                text(200, format!("unreachable {depth}"))
            }
            "/recurse" => {
                let depth = recurse_native(0);
                text(200, format!("unreachable {depth}"))
            }
            "/panic" => panic!("hostile plugin panicked on purpose"),
            "/forbidden" => {
                let target = query_param(&req.query, "url")
                    .unwrap_or_else(|| "http://169.254.169.254/latest/meta-data/".to_string());
                match get(&target) {
                    Ok(status) => text(200, format!("fetched {target}: {status}\n")),
                    Err(e) => text(403, format!("{}\n", describe(&e))),
                }
            }
            "/secret" => {
                let granted = env::get("AWS_SECRET_ACCESS_KEY").is_some();
                let wasi_env: Vec<String> = std::env::vars().map(|(k, _)| json_str(&k)).collect();
                let file = std::fs::read_to_string("/etc/passwd").map(|s| s.len());
                json(
                    200,
                    format!(
                        "{{\"granted_secret\":{granted},\"wasi_env\":[{}],\"etc_passwd\":{}}}",
                        wasi_env.join(","),
                        json_str(&format!("{file:?}"))
                    ),
                )
            }
            "/kv" => match kv::set("stolen", b"data") {
                Ok(()) => text(200, "kv write succeeded\n"),
                Err(e) => text(403, format!("kv refused: {e:?}\n")),
            },
            "/fetch-flood" => {
                let target = query_param(&req.query, "url").unwrap_or_default();
                let mut ok = 0u32;
                let refusal = loop {
                    match get(&target) {
                        Ok(_) => ok += 1,
                        Err(e) => break describe(&e),
                    }
                    if ok > 10_000 {
                        break "never refused".to_string();
                    }
                };
                text(429, format!("{ok} calls succeeded, then: {refusal}\n"))
            }
            "/log-flood" => {
                for i in 0..10_000 {
                    log::log(log::Level::Info, &format!("flood line {i}"));
                }
                for _ in 0..10_000 {
                    println!("stdout flood: {}", "x".repeat(100));
                }
                text(200, "flooded\n")
            }
            "/huge-response" => {
                let size: usize = query_param(&req.query, "bytes")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(4 << 20);
                plugbox_sdk::respond(200, "application/octet-stream", vec![b'z'; size])
            }
            "/spin" => {
                let ms: u64 = query_param(&req.query, "ms")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(10);
                let start = Instant::now();
                let mut n: u64 = 0;
                while start.elapsed() < Duration::from_millis(ms) {
                    n = black_box(n.wrapping_add(1));
                }
                text(200, format!("spun {ms}ms ({n} iterations)\n"))
            }
            "/sleep" => {
                // Blocking in `wasi:io/poll` runs no wasm, so neither fuel
                // nor the epoch deadline can interrupt it; the host must cap
                // the sleep itself.
                let ms: u64 = query_param(&req.query, "ms")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(3_600_000);
                let start = Instant::now();
                std::thread::sleep(Duration::from_millis(ms));
                text(200, format!("slept {}ms\n", start.elapsed().as_millis()))
            }
            _ => text(404, "unknown hostile route\n"),
        }
    }
}

plugbox_sdk::export!(Hostile with_types_in plugbox_sdk::bindings);
