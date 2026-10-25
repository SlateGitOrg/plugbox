//! Offline end-to-end demo: boots a real plugbox server on ephemeral ports
//! next to a local fixture upstream, drives it over HTTP, hot-reloads it,
//! and prints what happened. Run with `make demo`.

use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use plugbox::config::{ByteSize, ServerConfig};
use plugbox::engine::EngineSettings;
use plugbox::outbound::read_response;
use plugbox::{Registry, Runtime, RuntimeOptions};

fn upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let head = String::from_utf8_lossy(&buf);
            let target = head.split_whitespace().nth(1).unwrap_or("?").to_string();
            let body = format!(
                "{{\"item\":42,\"served_by\":\"fixture-upstream\",\"target\":\"{target}\"}}"
            );
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
        }
    });
    addr
}

fn http(
    addr: SocketAddr,
    method: &str,
    target: &str,
) -> (u16, Vec<(String, String)>, String, Duration) {
    let started = Instant::now();
    let mut s = TcpStream::connect(addr).expect("connect");
    write!(
        s,
        "{method} {target} HTTP/1.1\r\nhost: demo\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
    )
    .expect("write");
    let r = read_response(&mut BufReader::new(s), 1 << 20, method).expect("response");
    (
        r.status,
        r.headers,
        String::from_utf8_lossy(&r.body).into_owned(),
        started.elapsed(),
    )
}

fn show(addr: SocketAddr, method: &str, target: &str, note: &str) {
    let (status, headers, body, took) = http(addr, method, target);
    let err = headers
        .iter()
        .find(|(k, _)| k == "x-plugbox-error")
        .map(|(_, v)| format!(" [{v}]"))
        .unwrap_or_default();
    let mut body = body.trim_end().replace('\n', " ");
    if body.len() > 90 {
        body.truncate(90);
        body.push('…');
    }
    println!(
        "  {method:<4} {target:<44} -> {status}{err:<20} {:>7.2} ms  {body}",
        took.as_secs_f64() * 1e3
    );
    if !note.is_empty() {
        println!("       └ {note}");
    }
}

fn config(dist: &Path, up: SocketAddr, greeting: &str) -> String {
    let c = |n: &str| format!("{:?}", dist.join(format!("{n}.wasm")).display().to_string());
    format!(
        r#"
[[plugins]]
name = "hello"
route = "/hello"
component = {hello}
limits = {{ fuel = 10_000_000, timeout_ms = 50, memory = "8MiB" }}
[plugins.grants.env]
vars = {{ GREETING = "{greeting}" }}

[[plugins]]
name = "counter"
route = "/count"
component = {counter}
[plugins.grants.kv]
max_keys = 100

[[plugins]]
name = "fetcher"
route = "/api"
component = {fetcher}
[plugins.grants.env]
vars = {{ UPSTREAM = "http://{up}/v1" }}
[plugins.grants.http]
allow = ["http://{up}/v1/*"]

[[plugins]]
name = "hostile"
route = "/hostile"
component = {hostile}
limits = {{ fuel = 50_000_000, timeout_ms = 1000, memory = "16MiB" }}

[[plugins]]
name = "hostile-nofuel"
route = "/nofuel"
component = {hostile}
limits = {{ fuel = 0, timeout_ms = 40 }}
"#,
        hello = c("hello"),
        counter = c("counter"),
        fetcher = c("fetcher"),
        hostile = c("hostile"),
    )
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let dist = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugins/dist");
    if !dist.join("hello.wasm").exists() {
        eprintln!("plugins/dist is empty: run `make plugins` first");
        std::process::exit(1);
    }
    let work: PathBuf = std::env::temp_dir().join(format!("plugbox-demo-{}", std::process::id()));
    std::fs::create_dir_all(&work).expect("workdir");
    let cfg_path = work.join("plugbox.toml");
    let up = upstream();
    std::fs::write(&cfg_path, config(&dist, up, "hello from the edge")).expect("write config");

    let t0 = Instant::now();
    let runtime = Arc::new(
        Runtime::new(RuntimeOptions {
            engine: EngineSettings::default(),
            max_response_body: 1 << 20,
            ..RuntimeOptions::default()
        })
        .expect("runtime"),
    );
    let reg = Arc::new(Registry::load(runtime.clone(), &cfg_path).expect("load plugins"));
    println!("== plugbox demo ==");
    println!(
        "loaded {} plugins in {:.0} ms (pooling allocator, epoch tick 5 ms); fixture upstream on {up}",
        reg.snapshot().plugins().len(),
        t0.elapsed().as_secs_f64() * 1e3
    );
    for p in reg.snapshot().plugins() {
        println!(
            "  {:<15} {:<9} {}  grants: {}",
            p.name,
            p.route,
            p.version(),
            p.caps.summary()
        );
    }
    let server = plugbox::server::start(
        reg.clone(),
        &ServerConfig {
            listen: "127.0.0.1:0".parse().expect("addr"),
            admin_listen: Some("127.0.0.1:0".parse().expect("addr")),
            max_concurrency: 16,
            max_request_body: ByteSize(64 << 10),
            max_response_body: ByteSize(1 << 20),
        },
    )
    .await
    .expect("start server");
    let data = server.data_addr;
    let admin = server.admin_addr.expect("admin");
    println!("data plane http://{data}  admin plane http://{admin}\n");

    let steps = tokio::task::spawn_blocking(move || {
        println!("1. well-behaved plugins");
        show(data, "GET", "/hello?name=edge", "env grant: GREETING");
        show(data, "POST", "/count/hit/home", "");
        show(data, "POST", "/count/hit/home", "");
        show(
            data,
            "POST",
            "/count/hit/home",
            "KV state outlives each per-request instance",
        );
        show(
            data,
            "GET",
            "/api/proxy/items/42",
            "outbound HTTP via the allow-list",
        );

        println!("\n2. capability denials (typed errors, no trap)");
        show(
            data,
            "GET",
            "/api/fetch?url=http://169.254.169.254/latest/meta-data/",
            "cloud metadata: not on the allow-list",
        );
        show(
            data,
            "GET",
            "/api/fetch?url=http://127.0.0.1@169.254.169.254/",
            "userinfo confusion rejected by the URL parser",
        );
        show(
            data,
            "GET",
            "/hostile/secret",
            "no env, no host env, no filesystem",
        );
        show(data, "GET", "/hostile/kv", "no KV grant");

        println!("\n3. resource limits (instance discarded, host unaffected)");
        show(
            data,
            "GET",
            "/hostile/loop",
            "infinite loop, 50M fuel budget",
        );
        show(
            data,
            "GET",
            "/nofuel/loop",
            "infinite loop, fuel off, 40 ms epoch deadline",
        );
        show(
            data,
            "GET",
            "/hostile/bomb",
            "allocates until the 16 MiB budget refuses",
        );
        show(
            data,
            "GET",
            "/hostile/recurse",
            "native wasm stack exhausted",
        );
        show(data, "GET", "/hostile/panic", "Rust panic = guest abort");
        show(
            data,
            "GET",
            "/hostile/huge-response?bytes=4000000",
            "4 MB body > 1 MiB response limit",
        );
        show(
            data,
            "GET",
            "/hello?name=still-healthy",
            "host still serving",
        );

        println!("\n4. hot reload");
        std::fs::write(&cfg_path, config(&dist, up, "bonjour")).expect("rewrite config");
        let (status, _, body, _) = http(admin, "POST", "/reload");
        println!(
            "  POST /reload -> {status} {}",
            body.split_whitespace().collect::<Vec<_>>().join(" ")
        );
        show(
            data,
            "GET",
            "/hello?name=edge",
            "new grant, same compiled component",
        );
        let broken = work.join("broken.wasm");
        std::fs::write(&broken, b"not a component").expect("write broken");
        let bad = config(&dist, up, "bonjour").replacen(
            &format!("{:?}", dist.join("hello.wasm").display().to_string()),
            &format!("{:?}", broken.display().to_string()),
            1,
        );
        std::fs::write(&cfg_path, bad).expect("write bad config");
        let (status, _, body, _) = http(admin, "POST", "/reload");
        let first = body.lines().nth(1).unwrap_or("").trim();
        println!("  POST /reload (broken component) -> {status} {first}");
        show(
            data,
            "GET",
            "/hello?name=edge",
            "old snapshot keeps serving",
        );

        println!("\n5. admin plane");
        let (_, _, health, _) = http(admin, "GET", "/health");
        println!(
            "  GET /health -> {}",
            health.split_whitespace().collect::<Vec<_>>().join(" ")
        );
        let (_, _, metrics, _) = http(admin, "GET", "/metrics");
        println!("  GET /metrics (selected series):");
        for line in metrics.lines().filter(|l| {
            !l.starts_with('#')
                && (l.starts_with("plugbox_traps_total")
                    || l.starts_with("plugbox_capability_denials_total")
                    || l.starts_with("plugbox_reloads_total")
                    || l.starts_with("plugbox_pool_live_instances")
                    || l.starts_with("plugbox_outbound_requests_total"))
        }) {
            println!("    {line}");
        }
        let _ = std::fs::remove_dir_all(&work);
    })
    .await;
    server.shutdown().await;
    if steps.is_err() {
        eprintln!("demo failed");
        std::process::exit(1);
    }
    println!("\ndemo complete");
}
