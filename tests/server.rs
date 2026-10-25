//! End-to-end tests over real sockets: data plane, admin plane, shedding.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use plugbox::Registry;
use plugbox::config::{ByteSize, ServerConfig};
use plugbox::server::{RunningServer, start};

fn plugins_config() -> String {
    format!(
        r#"
[[plugins]]
name = "hello"
route = "/hello"
component = {}
[plugins.grants.env]
vars = {{ GREETING = "hey" }}

[[plugins]]
name = "hostile"
route = "/hostile"
component = {}
limits = {{ fuel = 0, timeout_ms = 1500 }}
"#,
        lit(&wasm("hello")),
        lit(&wasm("hostile"))
    )
}

fn server_cfg(max_concurrency: usize) -> ServerConfig {
    ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        admin_listen: Some("127.0.0.1:0".parse().unwrap()),
        max_concurrency,
        max_request_body: ByteSize(1024),
        max_response_body: ByteSize(1 << 20),
    }
}

struct Live {
    _dir: TempDir,
    _rt: tokio::runtime::Runtime,
    server: Option<RunningServer>,
    reg: Arc<Registry>,
}

impl Live {
    fn data(&self) -> std::net::SocketAddr {
        self.server.as_ref().unwrap().data_addr
    }
    fn admin(&self) -> std::net::SocketAddr {
        self.server.as_ref().unwrap().admin_addr.unwrap()
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if let Some(s) = self.server.take() {
            self._rt.block_on(s.shutdown());
        }
    }
}

fn live(max_concurrency: usize) -> Live {
    let dir = TempDir::new("server");
    let reg = registry(&dir, runtime(), &plugins_config());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let server = rt
        .block_on(start(reg.clone(), &server_cfg(max_concurrency)))
        .unwrap();
    Live {
        _dir: dir,
        _rt: rt,
        server: Some(server),
        reg,
    }
}

#[test]
fn routes_requests_to_plugins() {
    let l = live(8);
    let (status, headers, body) = http(l.data(), "GET", "/hello?name=net", b"");
    assert_eq!((status, body.as_str()), (200, "hey, net!\n"));
    assert_eq!(header(&headers, "x-plugbox-plugin"), Some("hello"));
    assert_eq!(
        header(&headers, "x-plugbox-version").map(str::len),
        Some(12)
    );
    assert_eq!(
        header(&headers, "content-type"),
        Some("text/plain; charset=utf-8")
    );

    let (status, _, body) = http(l.data(), "POST", "/hello/echo", b"ping");
    assert_eq!(status, 200);
    assert!(
        body.contains(r#""path":"/echo""#) && body.contains(r#""body":"ping""#),
        "{body}"
    );
    assert!(
        body.contains(r#"["host","test"]"#),
        "request headers are forwarded: {body}"
    );

    let (status, headers, _) = http(l.data(), "GET", "/nothing-here", b"");
    assert_eq!(status, 404);
    assert_eq!(header(&headers, "x-plugbox-error"), Some("no-route"));
    assert_eq!(http(l.data(), "GET", "/_plugbox/metrics", b"").0, 404);
}

#[test]
fn traps_map_to_gateway_errors() {
    let l = live(8);
    let (status, headers, body) = http(l.data(), "GET", "/hostile/loop", b"");
    assert_eq!(status, 504);
    assert_eq!(
        header(&headers, "x-plugbox-error"),
        Some("deadline-exceeded")
    );
    assert_eq!(
        body, "plugin error: deadline-exceeded\n",
        "no internals leak to clients"
    );
    let (status, headers, _) = http(l.data(), "GET", "/hostile/panic", b"");
    assert_eq!(status, 502);
    assert_eq!(header(&headers, "x-plugbox-error"), Some("guest-abort"));
    assert_eq!(http(l.data(), "GET", "/hello", b"").0, 200, "still healthy");
}

#[test]
fn oversized_bodies_are_rejected_before_the_sandbox() {
    let l = live(8);
    let (status, headers, _) = http(l.data(), "POST", "/hello/echo", &[b'a'; 4096]);
    assert_eq!(status, 413);
    assert_eq!(header(&headers, "x-plugbox-error"), Some("body-too-large"));
    assert_eq!(
        l.reg.runtime().metrics().requests.total(),
        0,
        "never reached a plugin"
    );
}

#[test]
fn excess_concurrency_is_shed() {
    let l = live(1);
    let addr = l.data();
    let slow = std::thread::spawn(move || http(addr, "GET", "/hostile/spin?ms=600", b"").0);
    std::thread::sleep(Duration::from_millis(150));
    let (status, headers, _) = http(addr, "GET", "/hello", b"");
    assert_eq!(status, 503);
    assert_eq!(header(&headers, "x-plugbox-error"), Some("overloaded"));
    assert_eq!(slow.join().unwrap(), 200);
    assert_eq!(http(addr, "GET", "/hello", b"").0, 200);
    assert_eq!(l.reg.runtime().metrics().shed.get(&["concurrency"]), 1);
}

/// A guest that sleeps in `wasi:io/poll` for an hour holds its concurrency
/// permit only until its own deadline, so it cannot starve other plugins.
#[test]
fn sleeping_plugins_release_their_permits_at_the_deadline() {
    let l = live(2);
    let addr = l.data();
    let started = std::time::Instant::now();
    let sleepers: Vec<_> = (0..2)
        .map(|_| {
            std::thread::spawn(move || {
                let (status, headers, _) = http(addr, "GET", "/hostile/sleep", b"");
                (
                    status,
                    header(&headers, "x-plugbox-error").map(str::to_owned),
                )
            })
        })
        .collect();
    for s in sleepers {
        assert_eq!(
            s.join().unwrap(),
            (504, Some("deadline-exceeded".to_owned()))
        );
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(4),
        "permits held past the 1.5 s deadline: {elapsed:?}"
    );
    assert_eq!(
        http(addr, "GET", "/hello", b"").0,
        200,
        "pool is free again"
    );
}

#[test]
fn admin_plane_reports_health_metrics_and_plugins() {
    let l = live(8);
    http(l.data(), "GET", "/hello", b"");
    http(l.data(), "GET", "/hostile/loop", b"");

    let (status, _, body) = http(l.admin(), "GET", "/health", b"");
    assert_eq!(status, 200);
    let health: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["plugins"], 2);
    assert_eq!(health["in_flight"], 0);
    assert_eq!(health["pool_live_instances"], 0);

    let (_, _, metrics) = http(l.admin(), "GET", "/metrics", b"");
    for needle in [
        r#"plugbox_requests_total{plugin="hello",status="200"} 1"#,
        r#"plugbox_requests_total{plugin="hostile",status="504"} 1"#,
        r#"plugbox_traps_total{plugin="hostile",kind="deadline-exceeded"} 1"#,
        "plugbox_pool_live_instances 0",
        "plugbox_config_generation 1",
    ] {
        assert!(metrics.contains(needle), "missing {needle}\n{metrics}");
    }

    let (_, _, body) = http(l.admin(), "GET", "/plugins", b"");
    let list: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(list["plugins"].as_array().unwrap().len(), 2);
    assert_eq!(list["plugins"][0]["name"], "hostile", "longest route first");
    assert_eq!(list["plugins"][1]["grants"], "env[GREETING]");

    let (status, _, body) = http(l.admin(), "POST", "/reload", b"");
    assert_eq!(status, 200, "{body}");
    let r: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(r["generation"], 2);
    assert_eq!(r["unchanged"].as_array().unwrap().len(), 2);

    std::fs::write(l.reg.config_path(), "not toml [").unwrap();
    let (status, _, body) = http(l.admin(), "POST", "/reload", b"");
    assert_eq!(status, 422);
    let r: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(r["active_generation"], 2);
    let (_, _, body) = http(l.admin(), "GET", "/health", b"");
    assert!(body.contains("invalid config"), "{body}");
    assert_eq!(http(l.admin(), "GET", "/nope", b"").0, 404);
}
