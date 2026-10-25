//! Shared helpers for integration tests.
#![allow(dead_code)]

use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use plugbox::engine::EngineSettings;
use plugbox::outbound::{HttpClient, Outbound, StaticResolver, read_response};
use plugbox::{Registry, Request, Response, Runtime, RuntimeOptions};

/// Path to a built sample plugin (`make plugins` puts them there).
pub fn wasm(name: &str) -> PathBuf {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("plugins/dist")
        .join(format!("{name}.wasm"));
    assert!(
        p.exists(),
        "{} is missing; run `make plugins` (needs the wasm32-wasip2 target)",
        p.display()
    );
    p
}

/// A scratch directory removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("plugbox-test-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn request(method: &str, path: &str, query: &str) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        query: query.into(),
        headers: vec![],
        body: vec![],
    }
}

pub fn body(r: &Response) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

/// Runtime with a resolver that knows `upstream.test` → 127.0.0.1.
pub fn runtime_with(settings: EngineSettings, cache_dir: Option<PathBuf>) -> Arc<Runtime> {
    let resolver = StaticResolver {
        entries: vec![("upstream.test".into(), "127.0.0.1".parse().unwrap())],
    };
    Arc::new(
        Runtime::new(RuntimeOptions {
            engine: settings,
            cache_dir,
            outbound: Outbound::new(Arc::new(resolver), Arc::new(HttpClient)),
            max_response_body: 1 << 20,
        })
        .unwrap(),
    )
}

pub fn runtime() -> Arc<Runtime> {
    runtime_with(
        EngineSettings {
            pool_size: 32,
            epoch_tick: Duration::from_millis(2),
            ..EngineSettings::default()
        },
        None,
    )
}

/// Write `config` into `dir/plugbox.toml` and load a registry from it.
pub fn registry(dir: &TempDir, rt: Arc<Runtime>, config: &str) -> Arc<Registry> {
    let path = dir.path("plugbox.toml");
    std::fs::write(&path, config).unwrap();
    Arc::new(Registry::load(rt, &path).unwrap())
}

/// TOML string literal for a path.
pub fn lit(p: &Path) -> String {
    format!("{:?}", p.display().to_string())
}

/// A tiny HTTP/1.1 upstream that answers every request with
/// `{"upstream":"ok","target":"<request target>"}`. Runs until the process exits.
pub fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let target = head.split_whitespace().nth(1).unwrap_or("?").to_string();
                let body = format!("{{\"upstream\":\"ok\",\"target\":\"{target}\"}}");
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    addr
}

/// Minimal blocking HTTP client for talking to a running server.
pub fn http(
    addr: SocketAddr,
    method: &str,
    target: &str,
    body: &[u8],
) -> (u16, Vec<(String, String)>, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(
        s,
        "{method} {target} HTTP/1.1\r\nhost: test\r\nconnection: close\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .unwrap();
    s.write_all(body).unwrap();
    let r = read_response(&mut BufReader::new(s), 16 << 20, method).unwrap();
    (
        r.status,
        r.headers,
        String::from_utf8_lossy(&r.body).into_owned(),
    )
}

pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}
