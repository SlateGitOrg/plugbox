//! Outbound HTTP for the `outbound-http` capability.
//!
//! [`Outbound::fetch`] is the single enforcement point. In order it:
//!
//! 1. checks the plugin has an HTTP grant at all;
//! 2. charges the per-request call budget;
//! 3. parses the URL strictly and matches it against the allow-list;
//! 4. validates method and headers (no CR/LF injection, no hop-by-hop);
//! 5. resolves the host and applies the [`AddressPolicy`] to *every*
//!    address, then hands only the vetted addresses to the client — the
//!    client never resolves again, which closes the DNS-rebinding window;
//! 6. caps the call's timeout by the request's remaining wall-clock budget
//!    and the response body by the grant's size limit.
//!
//! The built-in [`HttpClient`] speaks plain HTTP/1.1 over `std::net`. It is
//! blocking by design: host functions run on the thread executing the guest.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::allowlist::{Host, Scheme, Url};
use crate::capability::HttpCapability;

/// Header list.
pub type Headers = Vec<(String, String)>;

/// A request that passed every policy check.
#[derive(Clone, Debug)]
pub struct VettedRequest {
    pub method: String,
    pub url: Url,
    pub headers: Headers,
    pub body: Vec<u8>,
    /// The only addresses the client may connect to.
    pub addrs: Vec<SocketAddr>,
}

/// An upstream response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
}

/// Why a fetch failed (mirrors the WIT `http-error` variant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchError {
    NotGranted,
    Forbidden(String),
    InvalidUrl(String),
    QuotaExceeded,
    Timeout,
    Transport(String),
    TooLarge,
}

impl FetchError {
    /// Short label for metrics.
    pub fn label(&self) -> &'static str {
        match self {
            FetchError::NotGranted => "not_granted",
            FetchError::Forbidden(_) => "forbidden",
            FetchError::InvalidUrl(_) => "invalid_url",
            FetchError::QuotaExceeded => "quota_exceeded",
            FetchError::Timeout => "timeout",
            FetchError::Transport(_) => "transport",
            FetchError::TooLarge => "too_large",
        }
    }

    /// Whether this error is a capability/policy denial (audited).
    pub fn is_denial(&self) -> bool {
        matches!(
            self,
            FetchError::NotGranted | FetchError::Forbidden(_) | FetchError::QuotaExceeded
        )
    }
}

/// Name resolution, injectable so tests can simulate hostile DNS.
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// The operating system resolver.
#[derive(Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok((host, port).to_socket_addrs()?.collect())
    }
}

/// Sends a vetted request. Implementations must connect only to
/// `req.addrs`.
pub trait Upstream: Send + Sync {
    fn send(
        &self,
        req: &VettedRequest,
        timeout: Duration,
        max_body: usize,
    ) -> Result<UpstreamResponse, FetchError>;
}

/// What the guest asked for, before any checks.
#[derive(Clone, Debug, Default)]
pub struct FetchRequest {
    pub method: String,
    pub url: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl FetchRequest {
    /// A body-less `GET`.
    pub fn get(url: &str) -> FetchRequest {
        FetchRequest {
            method: "GET".into(),
            url: url.into(),
            ..FetchRequest::default()
        }
    }
}

/// Per-request outbound state: the call budget.
#[derive(Debug, Default)]
pub struct CallBudget {
    pub used: u32,
}

/// The outbound policy engine plus its transport.
#[derive(Clone)]
pub struct Outbound {
    resolver: Arc<dyn Resolver>,
    upstream: Arc<dyn Upstream>,
}

impl std::fmt::Debug for Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Outbound")
    }
}

impl Default for Outbound {
    fn default() -> Self {
        Outbound::new(Arc::new(SystemResolver), Arc::new(HttpClient))
    }
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "host",
    "content-length",
];

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

impl Outbound {
    /// Build from a resolver and transport.
    pub fn new(resolver: Arc<dyn Resolver>, upstream: Arc<dyn Upstream>) -> Outbound {
        Outbound { resolver, upstream }
    }

    /// Run every policy check, then send. `deadline` is the inbound
    /// request's wall-clock deadline.
    pub fn fetch(
        &self,
        cap: Option<&HttpCapability>,
        budget: &mut CallBudget,
        req: FetchRequest,
        deadline: Instant,
    ) -> Result<UpstreamResponse, FetchError> {
        let FetchRequest {
            method,
            url,
            headers,
            body,
        } = req;
        let cap = cap.ok_or(FetchError::NotGranted)?;
        if budget.used >= cap.max_requests {
            return Err(FetchError::QuotaExceeded);
        }
        budget.used += 1;
        let url = Url::parse(&url).map_err(FetchError::InvalidUrl)?;
        let rule = cap
            .allow
            .find(&url)
            .ok_or_else(|| FetchError::Forbidden(format!("{url} matches no allow rule")))?;
        let literal = rule.is_ip_literal();
        let method = method.to_ascii_uppercase();
        if !is_token(&method) {
            return Err(FetchError::InvalidUrl(format!("invalid method `{method}`")));
        }
        let mut clean = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            let name = name.to_ascii_lowercase();
            if !is_token(&name) || value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
                return Err(FetchError::InvalidUrl(format!("invalid header `{name}`")));
            }
            if !HOP_BY_HOP.contains(&name.as_str()) {
                clean.push((name, value));
            }
        }
        let addrs = match &url.host {
            Host::Ip(ip) => vec![SocketAddr::new(*ip, url.port)],
            Host::Name(name) => self
                .resolver
                .resolve(name, url.port)
                .map_err(|e| FetchError::Transport(format!("resolve {name}: {e}")))?,
        };
        if addrs.is_empty() {
            return Err(FetchError::Transport(format!("{} resolved to nothing", url.host)));
        }
        for a in &addrs {
            cap.policy
                .check(a.ip(), literal)
                .map_err(|why| FetchError::Forbidden(format!("{}: {why}", url.host)))?;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = remaining.min(cap.timeout);
        if timeout.is_zero() {
            return Err(FetchError::Timeout);
        }
        let req = VettedRequest {
            method,
            url,
            headers: clean,
            body,
            addrs,
        };
        self.upstream.send(&req, timeout, cap.max_response)
    }
}

/// Minimal blocking HTTP/1.1 client (`Connection: close`, plain HTTP only).
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpClient;

/// Largest accepted response head (status line + headers).
const MAX_HEAD: usize = 64 << 10;

impl Upstream for HttpClient {
    fn send(
        &self,
        req: &VettedRequest,
        timeout: Duration,
        max_body: usize,
    ) -> Result<UpstreamResponse, FetchError> {
        if req.url.scheme == Scheme::Https {
            return Err(FetchError::Transport(
                "https is not supported by the built-in client".into(),
            ));
        }
        let deadline = Instant::now() + timeout;
        let mut last_err = None;
        let mut stream = None;
        for addr in &req.addrs {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(FetchError::Timeout);
            }
            match TcpStream::connect_timeout(addr, left) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let mut stream = stream.ok_or_else(|| match last_err {
            Some(e) if is_timeout(&e) => FetchError::Timeout,
            Some(e) => FetchError::Transport(format!("connect: {e}")),
            None => FetchError::Transport("no address".into()),
        })?;
        let io_err = |e: io::Error| {
            if is_timeout(&e) {
                FetchError::Timeout
            } else {
                FetchError::Transport(e.to_string())
            }
        };
        stream.set_nodelay(true).map_err(io_err)?;
        set_timeouts(&stream, deadline).map_err(io_err)?;
        let mut head = format!(
            "{} {} HTTP/1.1\r\nhost: {}\r\nconnection: close\r\ncontent-length: {}\r\n",
            req.method,
            req.url.request_target(),
            req.url.host_header(),
            req.body.len()
        );
        for (k, v) in &req.headers {
            head.push_str(k);
            head.push_str(": ");
            head.push_str(v);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).map_err(io_err)?;
        stream.write_all(&req.body).map_err(io_err)?;
        let reader = DeadlineReader {
            inner: stream,
            deadline,
        };
        read_response(&mut BufReader::new(reader), max_body, &req.method)
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
}

fn set_timeouts(s: &TcpStream, deadline: Instant) -> io::Result<()> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline passed"));
    }
    s.set_read_timeout(Some(left))?;
    s.set_write_timeout(Some(left))
}

/// Re-arms the socket timeout before each read so the *total* time is
/// bounded by the deadline, not just each individual read.
struct DeadlineReader {
    inner: TcpStream,
    deadline: Instant,
}

impl Read for DeadlineReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        set_timeouts(&self.inner, self.deadline)?;
        self.inner.read(buf)
    }
}

fn transport(msg: impl Into<String>) -> FetchError {
    FetchError::Transport(msg.into())
}

fn map_read(e: io::Error) -> FetchError {
    if is_timeout(&e) {
        FetchError::Timeout
    } else {
        transport(e.to_string())
    }
}

fn read_line(r: &mut impl BufRead, budget: &mut usize) -> Result<String, FetchError> {
    let mut line = Vec::new();
    let limit = u64::try_from(*budget).unwrap_or(u64::MAX) + 1;
    r.take(limit).read_until(b'\n', &mut line).map_err(map_read)?;
    if line.len() > *budget {
        return Err(transport("response head too large"));
    }
    *budget -= line.len();
    if !line.ends_with(b"\n") {
        return Err(transport("connection closed mid-head"));
    }
    line.pop();
    if line.ends_with(b"\r") {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| transport("non-UTF-8 response head"))
}

/// Parse an HTTP/1.x response from `r`. Public for fuzzing/property tests.
pub fn read_response(
    r: &mut impl BufRead,
    max_body: usize,
    method: &str,
) -> Result<UpstreamResponse, FetchError> {
    let mut head_budget = MAX_HEAD;
    let status_line = read_line(r, &mut head_budget)?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(transport(format!("bad status line `{status_line}`")));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| (s.len() == 3).then(|| s.parse().ok()).flatten())
        .filter(|s| (100..=599).contains(s))
        .ok_or_else(|| transport(format!("bad status line `{status_line}`")))?;
    let mut headers = Vec::new();
    loop {
        let line = read_line(r, &mut head_budget)?;
        if line.is_empty() {
            break;
        }
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| transport(format!("bad header line `{line}`")))?;
        let k = k.trim().to_ascii_lowercase();
        if !is_token(&k) {
            return Err(transport(format!("bad header name `{k}`")));
        }
        headers.push((k, v.trim().to_string()));
    }
    let header = |name: &str| {
        headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
    };
    let no_body = method == "HEAD" || status == 204 || status == 304 || status < 200;
    let chunked = header("transfer-encoding")
        .iter()
        .any(|v| v.to_ascii_lowercase().contains("chunked"));
    let lengths = header("content-length");
    let body = if no_body {
        Vec::new()
    } else if chunked {
        read_chunked(r, max_body)?
    } else if let Some(first) = lengths.first() {
        if lengths.iter().any(|l| l != first) {
            return Err(transport("conflicting content-length headers"));
        }
        let n: usize = first
            .parse()
            .map_err(|_| transport(format!("bad content-length `{first}`")))?;
        if n > max_body {
            return Err(FetchError::TooLarge);
        }
        let mut body = vec![0; n];
        r.read_exact(&mut body).map_err(map_read)?;
        body
    } else {
        read_capped(r, max_body)?
    };
    headers.retain(|(k, _)| !HOP_BY_HOP.contains(&k.as_str()));
    Ok(UpstreamResponse {
        status,
        headers,
        body,
    })
}

fn read_capped(r: &mut impl Read, max_body: usize) -> Result<Vec<u8>, FetchError> {
    let mut body = Vec::new();
    let limit = u64::try_from(max_body).unwrap_or(u64::MAX) + 1;
    r.take(limit).read_to_end(&mut body).map_err(map_read)?;
    if body.len() > max_body {
        return Err(FetchError::TooLarge);
    }
    Ok(body)
}

fn read_chunked(r: &mut impl BufRead, max_body: usize) -> Result<Vec<u8>, FetchError> {
    let mut body = Vec::new();
    let mut line_budget = MAX_HEAD;
    loop {
        let line = read_line(r, &mut line_budget)?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| transport(format!("bad chunk size `{size_text}`")))?;
        if size == 0 {
            // Trailers until the blank line.
            while !read_line(r, &mut line_budget)?.is_empty() {}
            return Ok(body);
        }
        if body.len().saturating_add(size) > max_body {
            return Err(FetchError::TooLarge);
        }
        let start = body.len();
        body.resize(start + size, 0);
        r.read_exact(&mut body[start..]).map_err(map_read)?;
        if !read_line(r, &mut line_budget)?.is_empty() {
            return Err(transport("missing CRLF after chunk"));
        }
    }
}

/// Resolve every address of `host` that is an IP literal or comes from a
/// fixed table; used by tests and the demo to simulate DNS offline.
#[derive(Debug, Default, Clone)]
pub struct StaticResolver {
    pub entries: Vec<(String, IpAddr)>,
}

impl Resolver for StaticResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let found: Vec<SocketAddr> = self
            .entries
            .iter()
            .filter(|(h, _)| h == host)
            .map(|(_, ip)| SocketAddr::new(*ip, port))
            .collect();
        if found.is_empty() {
            Err(io::Error::new(io::ErrorKind::NotFound, "no such host"))
        } else {
            Ok(found)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::{AddressPolicy, AllowList};
    use proptest::prelude::*;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<VettedRequest>>,
    }

    impl Upstream for Recorder {
        fn send(
            &self,
            req: &VettedRequest,
            _timeout: Duration,
            _max: usize,
        ) -> Result<UpstreamResponse, FetchError> {
            self.seen.lock().unwrap().push(req.clone());
            Ok(UpstreamResponse {
                status: 200,
                headers: vec![],
                body: b"ok".to_vec(),
            })
        }
    }

    fn cap(rules: &[&str], allow_private: bool, max_requests: u32) -> HttpCapability {
        HttpCapability {
            allow: AllowList::parse(rules).unwrap(),
            policy: AddressPolicy { allow_private },
            max_requests,
            timeout: Duration::from_secs(1),
            max_response: 1024,
        }
    }

    fn outbound(dns: &[(&str, &str)]) -> (Outbound, Arc<Recorder>) {
        let rec = Arc::new(Recorder::default());
        let resolver = StaticResolver {
            entries: dns
                .iter()
                .map(|(h, ip)| (h.to_string(), ip.parse().unwrap()))
                .collect(),
        };
        (Outbound::new(Arc::new(resolver), rec.clone()), rec)
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn enforces_grant_budget_and_allow_list() {
        let (ob, rec) = outbound(&[]);
        let c = cap(&["http://127.0.0.1:9000/api/*"], false, 2);
        let mut b = CallBudget::default();
        let call = |b: &mut CallBudget, url: &str| {
            let mut r = FetchRequest::get(url);
            r.method = "get".into();
            ob.fetch(Some(&c), b, r, soon())
        };
        assert_eq!(
            ob.fetch(None, &mut b, FetchRequest::get("http://x/"), soon()),
            Err(FetchError::NotGranted)
        );
        assert!(call(&mut b, "http://127.0.0.1:9000/api/a").is_ok());
        assert!(matches!(
            call(&mut b, "http://127.0.0.1:9000/admin"),
            Err(FetchError::Forbidden(_))
        ));
        assert_eq!(call(&mut b, "http://127.0.0.1:9000/api/b"), Err(FetchError::QuotaExceeded));
        let seen = rec.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "GET");
        assert_eq!(seen[0].addrs, vec!["127.0.0.1:9000".parse().unwrap()]);
    }

    #[test]
    fn dns_answers_are_vetted_before_connecting() {
        let (ob, rec) = outbound(&[
            ("rebind.svc.test", "127.0.0.1"),
            ("meta.svc.test", "169.254.169.254"),
            ("mixed.svc.test", "93.184.215.14"),
            ("mixed.svc.test", "10.0.0.5"),
            ("public.svc.test", "93.184.215.14"),
        ]);
        let strict = cap(&["http://*.svc.test/*"], false, 10);
        let lax = cap(&["http://*.svc.test/*"], true, 10);
        let mut b = CallBudget::default();
        let mut go = |c: &HttpCapability, url: &str| {
            ob.fetch(Some(c), &mut b, FetchRequest::get(url), soon())
        };
        assert!(matches!(go(&strict, "http://rebind.svc.test/"), Err(FetchError::Forbidden(_))));
        assert!(matches!(go(&strict, "http://mixed.svc.test/"), Err(FetchError::Forbidden(_))));
        assert!(matches!(go(&lax, "http://meta.svc.test/"), Err(FetchError::Forbidden(_))));
        assert!(go(&lax, "http://rebind.svc.test/").is_ok());
        assert!(go(&strict, "http://public.svc.test/").is_ok());
        assert!(matches!(go(&strict, "http://nxdomain.svc.test/"), Err(FetchError::Transport(_))));
        assert_eq!(rec.seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn rejects_header_injection_and_strips_hop_by_hop() {
        let (ob, rec) = outbound(&[]);
        let c = cap(&["http://127.0.0.1:1/*"], false, 10);
        let mut b = CallBudget::default();
        let mut injected = FetchRequest::get("http://127.0.0.1:1/");
        injected.headers = vec![("x-a".into(), "v\r\nx-injected: 1".into())];
        let bad = ob.fetch(Some(&c), &mut b, injected, soon());
        assert!(matches!(bad, Err(FetchError::InvalidUrl(_))));
        let mut spaced = FetchRequest::get("http://127.0.0.1:1/");
        spaced.method = "GE T".into();
        let bad_method = ob.fetch(Some(&c), &mut b, spaced, soon());
        assert!(matches!(bad_method, Err(FetchError::InvalidUrl(_))));
        let mut post = FetchRequest::get("http://127.0.0.1:1/");
        post.method = "POST".into();
        post.headers = vec![("Host".into(), "evil".into()), ("X-Keep".into(), "1".into())];
        ob.fetch(Some(&c), &mut b, post, soon()).unwrap();
        assert_eq!(rec.seen.lock().unwrap()[0].headers, vec![("x-keep".to_string(), "1".to_string())]);
        let invalid = ob.fetch(Some(&c), &mut b, FetchRequest::get("not a url"), soon());
        assert!(matches!(invalid, Err(FetchError::InvalidUrl(_))));
    }

    #[test]
    fn exhausted_deadline_is_a_timeout() {
        let (ob, _) = outbound(&[]);
        let c = cap(&["http://127.0.0.1:1/*"], false, 10);
        let mut b = CallBudget::default();
        let past = Instant::now() - Duration::from_millis(1);
        assert_eq!(
            ob.fetch(Some(&c), &mut b, FetchRequest::get("http://127.0.0.1:1/"), past),
            Err(FetchError::Timeout)
        );
    }

    #[test]
    fn error_labels() {
        assert_eq!(FetchError::TooLarge.label(), "too_large");
        assert_eq!(FetchError::Timeout.label(), "timeout");
        assert_eq!(FetchError::NotGranted.label(), "not_granted");
        assert_eq!(FetchError::QuotaExceeded.label(), "quota_exceeded");
        assert_eq!(FetchError::Forbidden(String::new()).label(), "forbidden");
        assert_eq!(FetchError::InvalidUrl(String::new()).label(), "invalid_url");
        assert_eq!(FetchError::Transport(String::new()).label(), "transport");
        assert!(FetchError::Forbidden(String::new()).is_denial());
        assert!(!FetchError::Timeout.is_denial());
    }

    fn parse(raw: &str, max: usize) -> Result<UpstreamResponse, FetchError> {
        read_response(&mut Cursor::new(raw.as_bytes().to_vec()), max, "GET")
    }

    #[test]
    fn parses_length_chunked_and_eof_bodies() {
        let r = parse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: b\r\n\r\nhello", 10).unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
        assert_eq!(r.headers, vec![("x-a".to_string(), "b".to_string())]);
        let r = parse(
            "HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nT: x\r\n\r\n",
            10,
        )
        .unwrap();
        assert_eq!(r.body, b"abcde");
        let r = parse("HTTP/1.0 200 OK\r\n\r\nuntil eof", 100).unwrap();
        assert_eq!(r.body, b"until eof");
        let r = parse("HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\n", 10).unwrap();
        assert!(r.body.is_empty());
    }

    #[test]
    fn rejects_malformed_and_oversized_responses() {
        assert_eq!(parse("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n", 10), Err(FetchError::TooLarge));
        assert_eq!(parse("HTTP/1.1 200 OK\r\n\r\n0123456789A", 10), Err(FetchError::TooLarge));
        assert_eq!(
            parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\n", 10),
            Err(FetchError::TooLarge)
        );
        for bad in [
            "SSH-2.0\r\n\r\n",
            "HTTP/1.1 2000 OK\r\n\r\n",
            "HTTP/1.1 700 Nope\r\n\r\n",
            "HTTP/1.1 200 OK\r\nno colon\r\n\r\n",
            "HTTP/1.1 200 OK\r\nbad name: x\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            "HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nab\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab",
            "HTTP/1.1 200 OK\r\nX: y",
        ] {
            assert!(matches!(parse(bad, 10), Err(FetchError::Transport(_))), "{bad:?}");
        }
        let huge_head = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        assert!(matches!(parse(&huge_head, 10), Err(FetchError::Transport(_))));
    }

    #[test]
    fn http_client_round_trip_against_local_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            while !raw.ends_with(b"xyz") {
                let n = s.read(&mut buf).unwrap();
                assert!(n > 0, "client closed early");
                raw.extend_from_slice(&buf[..n]);
            }
            let req = String::from_utf8_lossy(&raw).to_string();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi")
                .unwrap();
            req
        });
        let req = VettedRequest {
            method: "POST".into(),
            url: Url::parse(&format!("http://{addr}/p?q=1")).unwrap(),
            headers: vec![("x-a".into(), "1".into())],
            body: b"xyz".to_vec(),
            addrs: vec![addr],
        };
        let resp = HttpClient.send(&req, Duration::from_secs(2), 100).unwrap();
        assert_eq!(resp.body, b"hi");
        let raw = server.join().unwrap();
        assert!(raw.starts_with("POST /p?q=1 HTTP/1.1\r\n"), "{raw}");
        assert!(raw.contains("x-a: 1\r\n"));
        assert!(raw.ends_with("\r\n\r\nxyz"));
    }

    #[test]
    fn http_client_times_out_on_silent_upstream() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let hold = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(400));
            drop(s);
        });
        let req = VettedRequest {
            method: "GET".into(),
            url: Url::parse(&format!("http://{addr}/")).unwrap(),
            headers: vec![],
            body: vec![],
            addrs: vec![addr],
        };
        let t0 = Instant::now();
        assert_eq!(
            HttpClient.send(&req, Duration::from_millis(100), 100),
            Err(FetchError::Timeout)
        );
        assert!(t0.elapsed() < Duration::from_millis(350));
        hold.join().unwrap();
    }

    #[test]
    fn http_client_refuses_https_and_reports_connect_errors() {
        let mut req = VettedRequest {
            method: "GET".into(),
            url: Url::parse("https://127.0.0.1/").unwrap(),
            headers: vec![],
            body: vec![],
            addrs: vec!["127.0.0.1:443".parse().unwrap()],
        };
        assert!(matches!(
            HttpClient.send(&req, Duration::from_secs(1), 10),
            Err(FetchError::Transport(m)) if m.contains("https")
        ));
        // A port nobody listens on: bind then drop to get a free one.
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        req.url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        req.addrs = vec![SocketAddr::from(([127, 0, 0, 1], port))];
        assert!(matches!(
            HttpClient.send(&req, Duration::from_secs(1), 10),
            Err(FetchError::Transport(_))
        ));
    }

    proptest! {
        #[test]
        fn response_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = read_response(&mut Cursor::new(bytes), 64, "GET");
        }

        #[test]
        fn chunked_encoding_round_trips(chunks in proptest::collection::vec("[a-z]{1,20}", 0..8)) {
            let mut raw = String::from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            for c in &chunks {
                raw.push_str(&format!("{:x}\r\n{c}\r\n", c.len()));
            }
            raw.push_str("0\r\n\r\n");
            let r = read_response(&mut Cursor::new(raw.into_bytes()), 1 << 20, "GET").unwrap();
            prop_assert_eq!(r.body, chunks.concat().into_bytes());
        }
    }
}
