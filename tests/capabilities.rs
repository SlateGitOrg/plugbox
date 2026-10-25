//! Capability grants work as configured — and only as configured — through
//! real guest components.

mod common;

use std::sync::Arc;

use common::*;
use plugbox::{Outcome, Registry};

fn setup(extra: &str) -> (TempDir, Arc<Registry>, std::net::SocketAddr) {
    let dir = TempDir::new("caps");
    let up = spawn_upstream();
    let hello = lit(&wasm("hello"));
    let counter = lit(&wasm("counter"));
    let fetcher = lit(&wasm("fetcher"));
    let cfg = format!(
        r#"
[[plugins]]
name = "hello"
route = "/hello"
component = {hello}
[plugins.grants.env]
vars = {{ GREETING = "howdy", REGION = "eu" }}

[[plugins]]
name = "counter"
route = "/count"
component = {counter}
[plugins.grants.kv]
namespace = "counter"
max_keys = 3

[[plugins]]
name = "counter-ro"
route = "/count-ro"
component = {counter}
[plugins.grants.kv]
namespace = "counter"
mode = "read-only"

[[plugins]]
name = "counter-none"
route = "/count-none"
component = {counter}

[[plugins]]
name = "fetcher"
route = "/fetch"
component = {fetcher}
[plugins.grants.env]
vars = {{ UPSTREAM = "http://{up}/api" }}
[plugins.grants.http]
allow = ["http://{up}/api/*", "http://upstream.test:{port}/*"]

[[plugins]]
name = "fetcher-private"
route = "/fetch-private"
component = {fetcher}
[plugins.grants.http]
allow = ["http://upstream.test:{port}/*"]
allow_private = true
{extra}
"#,
        port = up.port()
    );
    let reg = registry(&dir, runtime(), &cfg);
    (dir, reg, up)
}

fn call(reg: &Registry, plugin: &str, method: &str, path: &str, query: &str) -> (u16, String) {
    let p = reg.snapshot().get(plugin).unwrap();
    match reg
        .runtime()
        .invoke(&p, &request(method, path, query))
        .outcome
    {
        Outcome::Response(r) => (r.status, body(&r)),
        other => panic!("{plugin} {path}: {other:?}"),
    }
}

#[test]
fn env_grants_are_exact() {
    let (_d, reg, _) = setup("");
    assert_eq!(
        call(&reg, "hello", "GET", "/", "name=edge"),
        (200, "howdy, edge!\n".into())
    );
    assert_eq!(
        call(&reg, "hello", "GET", "/env", ""),
        (200, r#"{"granted":["GREETING","REGION"]}"#.into())
    );
    // A plugin without env grants sees nothing.
    assert_eq!(call(&reg, "fetcher-private", "GET", "/proxy/x", "").0, 500);
}

#[test]
fn echo_round_trips_request_fields() {
    let (_d, reg, _) = setup("");
    let p = reg.snapshot().get("hello").unwrap();
    let mut req = request("POST", "/echo", "a=1&b=%20");
    req.headers = vec![("x-trace".into(), "abc".into())];
    req.body = b"payload \"quoted\"".to_vec();
    let Outcome::Response(r) = reg.runtime().invoke(&p, &req).outcome else {
        panic!()
    };
    assert_eq!(
        body(&r),
        r#"{"method":"POST","path":"/echo","query":"a=1&b=%20","headers":[["x-trace","abc"]],"body":"payload \"quoted\""}"#
    );
}

#[test]
fn kv_state_persists_across_fresh_instances() {
    let (_d, reg, _) = setup("");
    for i in 1..=5 {
        assert_eq!(
            call(&reg, "counter", "POST", "/hit/home", ""),
            (200, format!(r#"{{"name":"home","count":{i}}}"#))
        );
    }
    assert_eq!(
        call(&reg, "counter", "GET", "/hit/home", "").1,
        r#"{"name":"home","count":5}"#
    );
    // Read-only grant on the same namespace can read but not write.
    assert_eq!(
        call(&reg, "counter-ro", "GET", "/hit/home", "").1,
        r#"{"name":"home","count":5}"#
    );
    assert_eq!(
        call(&reg, "counter-ro", "POST", "/hit/home", ""),
        (403, "kv is read-only\n".into())
    );
    // No grant at all.
    assert_eq!(
        call(&reg, "counter-none", "POST", "/hit/home", ""),
        (403, "kv not granted\n".into())
    );
    assert_eq!(
        call(&reg, "counter", "GET", "/keys", "").1,
        r#"{"counters":["home"]}"#
    );
    assert_eq!(call(&reg, "counter", "DELETE", "/hit/home", "").0, 200);
    assert_eq!(reg.runtime().kv().usage("counter"), (0, 0));
    let m = reg.runtime().metrics();
    assert_eq!(m.capability_denials.get(&["counter-ro", "kv"]), 1);
    assert_eq!(m.capability_denials.get(&["counter-none", "kv"]), 1);
}

#[test]
fn kv_quota_surfaces_as_a_guest_error() {
    let (_d, reg, _) = setup("");
    for k in ["a", "b", "c"] {
        assert_eq!(
            call(&reg, "counter", "POST", &format!("/hit/{k}"), "").0,
            200
        );
    }
    let (status, text) = call(&reg, "counter", "POST", "/hit/d", "");
    assert_eq!(status, 507);
    assert!(text.contains("maximum of 3 keys"), "{text}");
}

#[test]
fn outbound_http_reaches_only_allowed_upstreams() {
    let (_d, reg, up) = setup("");
    let (status, text) = call(&reg, "fetcher", "GET", "/proxy/items/7", "verbose=1");
    assert_eq!(status, 200);
    assert_eq!(
        text,
        r#"{"upstream":"ok","target":"/api/items/7?verbose=1"}"#
    );

    let outside = format!("url=http://{up}/admin");
    let (status, text) = call(&reg, "fetcher", "GET", "/fetch", &outside);
    assert_eq!(status, 403, "{text}");
    assert!(text.contains("matches no allow rule"));

    let dotdot = format!("url=http://{up}/api/../admin");
    assert_eq!(call(&reg, "fetcher", "GET", "/fetch", &dotdot).0, 400);

    // Hostname rule resolving to loopback: refused unless allow_private.
    let named = format!("url=http://upstream.test:{}/api/x", up.port());
    let (status, text) = call(&reg, "fetcher", "GET", "/fetch", &named);
    assert_eq!(status, 403);
    assert!(text.contains("private or loopback"), "{text}");
    let (status, text) = call(&reg, "fetcher-private", "GET", "/fetch", &named);
    assert_eq!(status, 200, "{text}");
    assert_eq!(text, r#"{"upstream":"ok","target":"/api/x"}"#);

    let m = reg.runtime().metrics();
    assert_eq!(m.outbound_requests.get(&["fetcher", "ok"]), 1);
    assert_eq!(m.outbound_requests.get(&["fetcher", "forbidden"]), 2);
    assert_eq!(m.outbound_requests.get(&["fetcher", "invalid_url"]), 1);
    assert_eq!(m.outbound_requests.get(&["fetcher-private", "ok"]), 1);
}

#[test]
fn unreachable_upstream_is_a_transport_error() {
    let (_d, reg, _) = setup("");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = TempDir::new("caps-closed");
    let cfg = format!(
        "[[plugins]]\nname = \"f\"\nroute = \"/\"\ncomponent = {}\n\
         [plugins.grants.http]\nallow = [\"http://127.0.0.1:{port}/*\"]\n",
        lit(&wasm("fetcher"))
    );
    let reg2 = registry(&dir, reg.runtime().clone(), &cfg);
    let (status, text) = call(
        &reg2,
        "f",
        "GET",
        "/fetch",
        &format!("url=http://127.0.0.1:{port}/"),
    );
    assert_eq!(status, 502, "{text}");
    assert!(text.starts_with("upstream error"), "{text}");
}
