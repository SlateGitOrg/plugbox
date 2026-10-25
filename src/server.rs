//! HTTP front end: the data plane (plugin traffic) and the admin plane
//! (health, metrics, plugin list, reload), on separate listeners.
//!
//! The async side (hyper on tokio) only parses, routes and buffers. Guest
//! code always runs on tokio's blocking pool via `spawn_blocking`, so a
//! plugin spinning until its deadline never stalls the accept loop or other
//! connections. Concurrency is bounded by a semaphore; excess requests are
//! shed immediately with 503 rather than queued without limit.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;

use crate::config::ServerConfig;
use crate::error::Result;
use crate::host::Request;
use crate::registry::Registry;
use crate::runtime::Outcome;

type Resp = hyper::Response<Full<Bytes>>;

/// Request headers never forwarded to plugins / response headers never
/// forwarded to clients.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "content-length",
];

/// Time allowed for a client to send request headers (slow-loris guard).
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared state of the data plane.
#[derive(Debug)]
struct DataPlane {
    registry: Arc<Registry>,
    permits: Arc<Semaphore>,
    max_request_body: usize,
}

fn text(status: u16, body: impl Into<String>) -> Resp {
    let mut r = hyper::Response::new(Full::new(Bytes::from(body.into())));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    r.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r
}

fn json_resp(status: u16, value: &serde_json::Value) -> Resp {
    let mut r = text(status, format!("{value:#}\n"));
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r
}

fn with_error(mut r: Resp, label: &str) -> Resp {
    if let Ok(v) = HeaderValue::from_str(label) {
        r.headers_mut().insert("x-plugbox-error", v);
    }
    r
}

impl DataPlane {
    async fn handle(self: Arc<Self>, req: hyper::Request<Incoming>) -> Resp {
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();
        if path.starts_with("/_plugbox") {
            return text(404, "not found\n");
        }
        let snapshot = self.registry.snapshot();
        let Some((plugin, sub_path)) = snapshot.route(&path) else {
            return with_error(text(404, "no plugin is mounted here\n"), "no-route");
        };
        drop(snapshot);
        let method = req.method().as_str().to_string();
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .filter(|(k, _)| !HOP_BY_HOP.contains(&k.as_str()))
            .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
            .collect();
        let body = match Limited::new(req.into_body(), self.max_request_body)
            .collect()
            .await
        {
            Ok(b) => b.to_bytes().to_vec(),
            Err(_) => {
                return with_error(text(413, "request body too large\n"), "body-too-large");
            }
        };
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            self.registry.runtime().metrics().shed.inc(&["concurrency"]);
            return with_error(text(503, "overloaded, retry later\n"), "overloaded");
        };
        let request = Request {
            method,
            path: sub_path,
            query,
            headers,
            body,
        };
        let registry = self.registry.clone();
        let task_plugin = plugin.clone();
        let invocation = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            registry.runtime().invoke(&task_plugin, &request)
        })
        .await;
        let Ok(invocation) = invocation else {
            return with_error(text(500, "internal error\n"), "internal");
        };
        let mut resp = match invocation.outcome {
            Outcome::Response(r) => {
                let mut out = hyper::Response::new(Full::new(Bytes::from(r.body)));
                *out.status_mut() =
                    StatusCode::from_u16(r.status).unwrap_or(StatusCode::BAD_GATEWAY);
                for (k, v) in r.headers {
                    let k = k.to_ascii_lowercase();
                    if HOP_BY_HOP.contains(&k.as_str()) || k.starts_with("x-plugbox-") {
                        continue;
                    }
                    if let (Ok(name), Ok(value)) =
                        (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v))
                    {
                        out.headers_mut().append(name, value);
                    }
                }
                out
            }
            ref other => {
                let label = other.error_label().unwrap_or("error");
                with_error(
                    text(other.http_status(), format!("plugin error: {label}\n")),
                    label,
                )
            }
        };
        let h = resp.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&plugin.name) {
            h.insert("x-plugbox-plugin", v);
        }
        if let Ok(v) = HeaderValue::from_str(plugin.version()) {
            h.insert("x-plugbox-version", v);
        }
        resp
    }
}

/// Admin plane: `/health`, `/metrics`, `/plugins`, `POST /reload`.
async fn admin(registry: Arc<Registry>, req: hyper::Request<Incoming>) -> Resp {
    let rt = registry.runtime().clone();
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") => {
            let snap = registry.snapshot();
            json_resp(
                200,
                &json!({
                    "status": "ok",
                    "generation": snap.generation,
                    "plugins": snap.plugins().len(),
                    "in_flight": rt.metrics().in_flight.get(),
                    "pool_live_instances": rt.pool_live_instances(),
                    "last_reload_error": registry.last_error(),
                }),
            )
        }
        (&Method::GET, "/metrics") => {
            let mut body = rt.metrics().render();
            if let Some(live) = rt.pool_live_instances() {
                body.push_str(&format!(
                    "# HELP plugbox_pool_live_instances Component instances currently allocated in the pool.\n\
                     # TYPE plugbox_pool_live_instances gauge\nplugbox_pool_live_instances {live}\n"
                ));
            }
            let mut r = text(200, body);
            r.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4"),
            );
            r
        }
        (&Method::GET, "/plugins") => {
            let snap = registry.snapshot();
            let list: Vec<_> = snap
                .plugins()
                .iter()
                .map(|p| {
                    json!({
                        "name": &*p.name,
                        "route": p.route,
                        "version": p.version(),
                        "generation": p.generation,
                        "component": p.component_path.display().to_string(),
                        "size_bytes": p.compiled.size,
                        "compile_ms": p.compiled.compile_time.as_secs_f64() * 1e3,
                        "from_cache": p.compiled.from_cache,
                        "grants": p.caps.summary(),
                        "limits": {
                            "fuel": p.limits.fuel,
                            "timeout_ms": p.limits.timeout_ms,
                            "memory_bytes": p.limits.memory.0,
                        },
                        "imports": p.compiled.report.imports,
                    })
                })
                .collect();
            json_resp(200, &json!({ "generation": snap.generation, "plugins": list }))
        }
        (&Method::POST, "/reload") => {
            let reg = registry.clone();
            match tokio::task::spawn_blocking(move || reg.reload()).await {
                Ok(Ok(r)) => json_resp(
                    200,
                    &json!({
                        "generation": r.generation,
                        "added": r.added,
                        "removed": r.removed,
                        "updated": r.updated,
                        "rebound": r.rebound,
                        "unchanged": r.unchanged,
                        "warnings": r.warnings,
                    }),
                ),
                Ok(Err(e)) => json_resp(
                    422,
                    &json!({
                        "error": e.to_string(),
                        "active_generation": registry.snapshot().generation,
                    }),
                ),
                Err(_) => text(500, "reload task failed\n"),
            }
        }
        _ => text(404, "admin endpoints: GET /health /metrics /plugins, POST /reload\n"),
    }
}

async fn accept_loop<F, Fut>(listener: TcpListener, mut stop: oneshot::Receiver<()>, handler: F)
where
    F: Fn(hyper::Request<Incoming>) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<Output = Resp> + Send + 'static,
{
    loop {
        tokio::select! {
            _ = &mut stop => break,
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else { continue };
                let handler = handler.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let handler = handler.clone();
                        async move { Ok::<_, Infallible>(handler(req).await) }
                    });
                    let conn = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_TIMEOUT)
                        .serve_connection(TokioIo::new(stream), service);
                    if let Err(e) = conn.await {
                        tracing::debug!(error = %e, "connection ended with error");
                    }
                });
            }
        }
    }
}

/// A running server; dropping it (or calling [`RunningServer::shutdown`])
/// stops accepting new connections.
#[derive(Debug)]
pub struct RunningServer {
    pub data_addr: SocketAddr,
    pub admin_addr: Option<SocketAddr>,
    stops: Vec<oneshot::Sender<()>>,
    tasks: Vec<JoinHandle<()>>,
}

impl RunningServer {
    /// Stop accepting and wait for the accept loops to exit.
    pub async fn shutdown(mut self) {
        for s in self.stops.drain(..) {
            let _ = s.send(());
        }
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
    }
}

/// Bind both listeners and start serving. Must be called inside a tokio
/// runtime. Port 0 binds an ephemeral port (see the returned addresses).
pub async fn start(registry: Arc<Registry>, cfg: &ServerConfig) -> Result<RunningServer> {
    let data = TcpListener::bind(cfg.listen).await?;
    let data_addr = data.local_addr()?;
    let plane = Arc::new(DataPlane {
        registry: registry.clone(),
        permits: Arc::new(Semaphore::new(cfg.max_concurrency)),
        max_request_body: cfg.max_request_body.as_usize(),
    });
    let (stop_tx, stop_rx) = oneshot::channel();
    let mut stops = vec![stop_tx];
    let mut tasks = vec![tokio::spawn(accept_loop(data, stop_rx, move |req| {
        plane.clone().handle(req)
    }))];
    let mut admin_addr = None;
    if let Some(addr) = cfg.admin_listen {
        let listener = TcpListener::bind(addr).await?;
        admin_addr = Some(listener.local_addr()?);
        let (tx, rx) = oneshot::channel();
        stops.push(tx);
        let reg = registry.clone();
        tasks.push(tokio::spawn(accept_loop(listener, rx, move |req| {
            admin(reg.clone(), req)
        })));
    }
    tracing::info!(%data_addr, ?admin_addr, "plugbox listening");
    Ok(RunningServer {
        data_addr,
        admin_addr,
        stops,
        tasks,
    })
}
