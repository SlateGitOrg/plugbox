//! Outbound-HTTP allow-list: a strict URL parser, allow rules, and the
//! post-resolution address policy.
//!
//! The parser is deliberately narrower than WHATWG URL parsing. Anything that
//! is a known allow-list bypass in other systems is rejected outright rather
//! than normalised:
//!
//! * userinfo (`http://allowed.example@evil.example/`)
//! * percent-encoding, backslashes or whitespace in the authority
//! * non-canonical numeric hosts (`http://2130706433/`, `http://0x7f.1/`,
//!   `http://127.1/`)
//! * dot segments in the path (`/api/../admin`, `/api/%2e%2e/admin`)
//!
//! After DNS resolution the [`AddressPolicy`] is applied to every address, so
//! a hostname rule cannot be turned into an SSRF by pointing DNS at loopback
//! or at the cloud metadata service.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// URL schemes the allow-list understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn parse(s: &str) -> Option<Scheme> {
        match s.to_ascii_lowercase().as_str() {
            "http" => Some(Scheme::Http),
            "https" => Some(Scheme::Https),
            _ => None,
        }
    }

    /// The scheme's default port.
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        })
    }
}

/// A host: a DNS name or an IP literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {
    /// Lower-cased DNS name without a trailing dot.
    Name(String),
    Ip(IpAddr),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Name(n) => f.write_str(n),
            Host::Ip(IpAddr::V4(ip)) => write!(f, "{ip}"),
            Host::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
        }
    }
}

/// A parsed absolute `http(s)` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub scheme: Scheme,
    pub host: Host,
    pub port: u16,
    /// Path, always starting with `/`.
    pub path: String,
    /// Query without `?`, possibly empty.
    pub query: String,
}

impl Url {
    /// Parse an absolute URL, rejecting ambiguous forms (see module docs).
    pub fn parse(input: &str) -> Result<Url, String> {
        if input.len() > 4096 {
            return Err("url longer than 4096 bytes".into());
        }
        if input.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err("url contains whitespace or control characters".into());
        }
        let (scheme, rest) = input
            .split_once("://")
            .ok_or_else(|| "url must be absolute (scheme://host/...)".to_string())?;
        let scheme =
            Scheme::parse(scheme).ok_or_else(|| format!("unsupported scheme `{scheme}`"))?;
        let rest = rest.split('#').next().unwrap_or("");
        let auth_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(auth_end);
        let (host, port) = parse_authority(authority, scheme)?;
        let (path, query) = match tail.split_once('?') {
            Some((p, q)) => (p, q),
            None => (tail, ""),
        };
        let path = if path.is_empty() { "/" } else { path };
        check_path(path)?;
        Ok(Url {
            scheme,
            host,
            port,
            path: path.to_string(),
            query: query.to_string(),
        })
    }

    /// `host:port` suitable for a `Host` header (port omitted if default).
    pub fn host_header(&self) -> String {
        if self.port == self.scheme.default_port() {
            self.host.to_string()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Request target (`/path?query`).
    pub fn request_target(&self) -> String {
        if self.query.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, self.query)
        }
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}{}",
            self.scheme,
            self.host_header(),
            self.request_target()
        )
    }
}

fn parse_authority(authority: &str, scheme: Scheme) -> Result<(Host, u16), String> {
    if authority.is_empty() {
        return Err("missing host".into());
    }
    if authority.contains(['@', '\\', '%']) {
        return Err("userinfo, backslashes and percent-escapes are not allowed in the host".into());
    }
    let (host_part, port_part) = if let Some(after) = authority.strip_prefix('[') {
        let (v6, after) = after
            .split_once(']')
            .ok_or_else(|| "unterminated IPv6 literal".to_string())?;
        let ip: Ipv6Addr = v6.parse().map_err(|_| format!("bad IPv6 literal `{v6}`"))?;
        let port = match after {
            "" => None,
            p => Some(
                p.strip_prefix(':')
                    .ok_or_else(|| "garbage after IPv6 literal".to_string())?,
            ),
        };
        (Host::Ip(IpAddr::V6(ip)), port)
    } else {
        let (h, p) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        (parse_host(h)?, p)
    };
    let port = match port_part {
        None => scheme.default_port(),
        Some(p) => parse_port(p)?,
    };
    Ok((host_part, port))
}

fn parse_port(p: &str) -> Result<u16, String> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("bad port `{p}`"));
    }
    match p.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("bad port `{p}`")),
        Ok(n) => Ok(n),
    }
}

/// Parse a DNS name or dotted-quad IPv4 literal.
fn parse_host(h: &str) -> Result<Host, String> {
    let h = h.strip_suffix('.').unwrap_or(h).to_ascii_lowercase();
    if h.is_empty() || h.len() > 253 {
        return Err("bad host length".into());
    }
    if !h
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(format!("host `{h}` contains invalid characters"));
    }
    // Anything whose last label is numeric (or hex) must be a canonical
    // dotted quad; this rejects `2130706433`, `127.1`, `0x7f.0.0.1`, `0177.0.0.1`.
    let last = h.rsplit('.').next().unwrap_or("");
    let numeric_looking = last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x");
    if numeric_looking {
        let ip: Ipv4Addr = h
            .parse()
            .map_err(|_| format!("non-canonical numeric host `{h}`"))?;
        return Ok(Host::Ip(IpAddr::V4(ip)));
    }
    for label in h.split('.') {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return Err(format!("bad DNS label in `{h}`"));
        }
    }
    Ok(Host::Name(h))
}

fn check_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err("path must start with `/`".into());
    }
    for seg in path.split('/') {
        let decoded = seg.to_ascii_lowercase().replace("%2e", ".");
        if decoded == "." || decoded == ".." {
            return Err("dot segments are not allowed in the path".into());
        }
    }
    if path.to_ascii_lowercase().contains("%2f") || path.contains('\\') {
        return Err("encoded slashes and backslashes are not allowed in the path".into());
    }
    Ok(())
}

/// Host part of an allow rule.
#[derive(Clone, Debug, PartialEq, Eq)]
enum HostPattern {
    Exact(Host),
    /// `*.example.com`: any strict subdomain of `example.com`.
    Subdomains(String),
}

/// Path part of an allow rule.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PathPattern {
    Any,
    Prefix(String),
    Exact(String),
}

/// One allow rule, e.g. `http://127.0.0.1:9000/api/*`.
///
/// * The scheme must match exactly.
/// * Port: explicit `:N`, `:*` for any, or omitted = the scheme default.
/// * Path: omitted or `/*` = any; trailing `*` = prefix; otherwise exact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowRule {
    text: String,
    scheme: Scheme,
    host: HostPattern,
    /// `None` = any port.
    port: Option<u16>,
    path: PathPattern,
}

impl AllowRule {
    /// Parse a rule.
    pub fn parse(rule: &str) -> Result<AllowRule, String> {
        let (scheme, rest) = rule
            .split_once("://")
            .ok_or_else(|| "rule must look like scheme://host[:port][/path]".to_string())?;
        let scheme =
            Scheme::parse(scheme).ok_or_else(|| format!("unsupported scheme `{scheme}`"))?;
        let auth_end = rest.find('/').unwrap_or(rest.len());
        let (authority, path) = rest.split_at(auth_end);
        let port_spec = |p: &str| -> Result<Option<u16>, String> {
            match p {
                "" => Ok(Some(scheme.default_port())),
                ":*" => Ok(None),
                p => match p.strip_prefix(':') {
                    Some(n) => parse_port(n).map(Some),
                    None => Err(format!("garbage after host: `{p}`")),
                },
            }
        };
        let (host_text, port) = if authority.starts_with('[') {
            let close = authority
                .find(']')
                .ok_or_else(|| "unterminated IPv6 literal".to_string())?;
            let (h, p) = authority.split_at(close + 1);
            (h, port_spec(p)?)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, port_spec(&format!(":{p}"))?),
                None => (authority, Some(scheme.default_port())),
            }
        };
        let host = if let Some(suffix) = host_text.strip_prefix("*.") {
            match parse_host(suffix)? {
                Host::Name(n) if n.contains('.') => HostPattern::Subdomains(n),
                _ => return Err("wildcards need a registrable suffix like *.example.com".into()),
            }
        } else if host_text.contains('*') {
            return Err("only a leading `*.` wildcard is supported".into());
        } else if let Some(v6) = host_text
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
        {
            let ip: Ipv6Addr = v6.parse().map_err(|_| format!("bad IPv6 literal `{v6}`"))?;
            HostPattern::Exact(Host::Ip(IpAddr::V6(ip)))
        } else {
            if host_text.contains(['@', '%', '\\']) {
                return Err("invalid characters in rule host".into());
            }
            HostPattern::Exact(parse_host(host_text)?)
        };
        let path = match path {
            "" | "/*" => PathPattern::Any,
            p if p.ends_with('*') => {
                let prefix = &p[..p.len() - 1];
                if prefix.contains('*') {
                    return Err("only a trailing `*` is supported in rule paths".into());
                }
                check_path(prefix)?;
                PathPattern::Prefix(prefix.to_string())
            }
            p => {
                if p.contains('*') {
                    return Err("only a trailing `*` is supported in rule paths".into());
                }
                check_path(p)?;
                PathPattern::Exact(p.to_string())
            }
        };
        Ok(AllowRule {
            text: rule.to_string(),
            scheme,
            host,
            port,
            path,
        })
    }

    /// Whether `url` is permitted by this rule.
    pub fn matches(&self, url: &Url) -> bool {
        if url.scheme != self.scheme {
            return false;
        }
        if self.port.is_some_and(|p| p != url.port) {
            return false;
        }
        let host_ok = match (&self.host, &url.host) {
            (HostPattern::Exact(h), u) => h == u,
            (HostPattern::Subdomains(suffix), Host::Name(n)) => n
                .strip_suffix(suffix.as_str())
                .is_some_and(|head| head.len() > 1 && head.ends_with('.')),
            (HostPattern::Subdomains(_), Host::Ip(_)) => false,
        };
        host_ok
            && match &self.path {
                PathPattern::Any => true,
                PathPattern::Prefix(p) => url.path.starts_with(p.as_str()),
                PathPattern::Exact(p) => url.path == *p,
            }
    }

    /// Whether the rule names an IP literal (no DNS involved).
    pub fn is_ip_literal(&self) -> bool {
        matches!(self.host, HostPattern::Exact(Host::Ip(_)))
    }

    /// The rule as written in the config.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// A set of allow rules; a URL is permitted if any rule matches.
#[derive(Clone, Debug, Default)]
pub struct AllowList {
    rules: Vec<AllowRule>,
}

impl AllowList {
    /// Parse every rule; fails on the first bad one.
    pub fn parse<S: AsRef<str>>(rules: &[S]) -> Result<AllowList, String> {
        let rules = rules
            .iter()
            .map(|r| AllowRule::parse(r.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AllowList { rules })
    }

    /// The first rule matching `url`, if any.
    pub fn find(&self, url: &Url) -> Option<&AllowRule> {
        self.rules.iter().find(|r| r.matches(url))
    }
}

/// What to do with the addresses a permitted host resolves to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressPolicy {
    /// Allow loopback / RFC1918 / unique-local targets reached via a
    /// hostname rule. IP-literal rules are trusted as written.
    pub allow_private: bool,
}

impl AddressPolicy {
    /// Check one resolved address. `literal_rule` is true when the matching
    /// rule named the IP explicitly.
    pub fn check(&self, ip: IpAddr, literal_rule: bool) -> Result<(), String> {
        let ip = canonical(ip);
        if is_always_denied(ip) {
            return Err(format!(
                "{ip} is a link-local, metadata, multicast or unspecified address"
            ));
        }
        if !literal_rule && !self.allow_private && is_private(ip) {
            return Err(format!(
                "{ip} is a private or loopback address (set allow_private to permit)"
            ));
        }
        Ok(())
    }
}

/// Unwrap IPv4-mapped IPv6 (`::ffff:a.b.c.d`) so v4 rules apply.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn is_always_denied(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_link_local() || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            (v6.segments()[0] & 0xffc0) == 0xfe80 || v6.is_unspecified() || v6.is_multicast()
        }
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback() || v4.is_private() || (a == 100 && (64..128).contains(&b)) || a == 0
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn parses_ordinary_urls() {
        let u = url("HTTP://Api.Example.COM.:8080/v1/items?id=3#frag");
        assert_eq!(u.scheme, Scheme::Http);
        assert_eq!(u.host, Host::Name("api.example.com".into()));
        assert_eq!(u.port, 8080);
        assert_eq!(u.path, "/v1/items");
        assert_eq!(u.query, "id=3");
        assert_eq!(u.to_string(), "http://api.example.com:8080/v1/items?id=3");
        let u = url("https://[::1]/x");
        assert_eq!(u.port, 443);
        assert_eq!(u.host_header(), "[::1]");
        assert_eq!(url("http://10.0.0.1:81").request_target(), "/");
        assert_eq!(url("http://h?q").path, "/");
    }

    #[test]
    fn rejects_known_bypass_shapes() {
        for bad in [
            "http://allowed.example@evil.example/",
            "http://2130706433/",
            "http://127.1/",
            "http://0x7f.0.0.1/",
            "http://0177.0.0.1/",
            "http://evil%2eexample/",
            "http://a\\b/",
            "http://h/api/../admin",
            "http://h/api/%2E%2e/admin",
            "http://h/api%2fadmin",
            "http://h /",
            "ftp://h/",
            "//h/",
            "http:///x",
            "http://h:0/",
            "http://h:99999/",
            "http://h:/",
            "http://[::1/",
            "http://[::1]x/",
            "http://-bad.example/",
            "http://a..b/",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad} should be rejected");
        }
        assert!(Url::parse(&format!("http://h/{}", "a".repeat(5000))).is_err());
    }

    #[test]
    fn rule_matching() {
        let r = AllowRule::parse("http://127.0.0.1:9000/api/*").unwrap();
        assert!(r.is_ip_literal());
        assert!(r.matches(&url("http://127.0.0.1:9000/api/x?y=1")));
        assert!(!r.matches(&url("http://127.0.0.1:9000/apix")));
        assert!(!r.matches(&url("http://127.0.0.1:9001/api/x")));
        assert!(!r.matches(&url("https://127.0.0.1:9000/api/x")));

        let r = AllowRule::parse("https://*.example.com").unwrap();
        assert!(r.matches(&url("https://a.example.com/anything")));
        assert!(r.matches(&url("https://a.b.example.com/")));
        assert!(!r.matches(&url("https://example.com/")));
        assert!(!r.matches(&url("https://badexample.com/")));
        assert!(!r.matches(&url("https://a.example.com:8443/")));

        let r = AllowRule::parse("http://svc.internal:*/health").unwrap();
        assert!(r.matches(&url("http://svc.internal:1234/health")));
        assert!(!r.matches(&url("http://svc.internal:1234/health/x")));

        let r = AllowRule::parse("http://[::1]:8080/*").unwrap();
        assert!(r.matches(&url("http://[::1]:8080/a")));
        assert_eq!(r.as_str(), "http://[::1]:8080/*");
    }

    #[test]
    fn rejects_bad_rules() {
        for bad in [
            "127.0.0.1",
            "gopher://x",
            "http://*",
            "http://*.com",
            "http://a*.example.com",
            "http://x/a*b*",
            "http://x/a*b",
            "http://x:0",
            "http://u@x",
            "http://[zz]",
            "http://x/../y*",
        ] {
            assert!(AllowRule::parse(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn allow_list_finds_first_match() {
        let list = AllowList::parse(&["http://a.test/*", "http://b.test/x"]).unwrap();
        assert!(list.find(&url("http://a.test/q")).is_some());
        assert!(list.find(&url("http://b.test/x")).is_some());
        assert!(list.find(&url("http://b.test/y")).is_none());
        assert!(AllowList::parse(&["bad"]).is_err());
    }

    #[test]
    fn address_policy() {
        let strict = AddressPolicy {
            allow_private: false,
        };
        let lax = AddressPolicy {
            allow_private: true,
        };
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        // Metadata / link-local is refused even for literal rules.
        assert!(strict.check(ip("169.254.169.254"), true).is_err());
        assert!(lax.check(ip("fe80::1"), false).is_err());
        assert!(lax.check(ip("0.0.0.0"), false).is_err());
        assert!(lax.check(ip("::ffff:169.254.169.254"), true).is_err());
        assert!(lax.check(ip("224.0.0.1"), true).is_err());
        // Private targets need a literal rule or allow_private.
        for p in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "100.64.0.1",
            "::1",
            "fd00::1",
        ] {
            assert!(strict.check(ip(p), false).is_err(), "{p}");
            assert!(strict.check(ip(p), true).is_ok(), "{p}");
            assert!(lax.check(ip(p), false).is_ok(), "{p}");
        }
        assert!(strict.check(ip("93.184.215.14"), false).is_ok());
        assert!(strict.check(ip("2606:4700::1"), false).is_ok());
    }

    proptest! {
        #[test]
        fn parser_never_panics(s in "\\PC{0,80}") {
            let _ = Url::parse(&s);
            let _ = AllowRule::parse(&s);
        }

        #[test]
        fn parsed_urls_round_trip(
            host in "[a-z][a-z0-9]{0,10}(\\.[a-z][a-z0-9]{0,10}){0,3}",
            port in 1u16..,
            path in "(/[a-zA-Z0-9_~-]{1,8}){0,4}",
            query in "[a-z0-9=&]{0,12}",
        ) {
            let text = format!("http://{host}:{port}{path}?{query}");
            let u = Url::parse(&text).unwrap();
            let again = Url::parse(&u.to_string()).unwrap();
            prop_assert_eq!(u, again);
        }

        #[test]
        fn userinfo_is_always_rejected(a in "[a-z]{1,8}", b in "[a-z]{1,8}") {
            let text = format!("http://{a}.test@{b}.test/");
            prop_assert!(Url::parse(&text).is_err());
        }

        #[test]
        fn wildcard_never_matches_lookalike_apex(label in "[a-z]{1,10}") {
            let r = AllowRule::parse("https://*.example.com").unwrap();
            let lookalike = format!("https://{label}example.com/");
            prop_assert!(!r.matches(&Url::parse(&lookalike).unwrap()));
            let sub = format!("https://{label}.example.com/");
            prop_assert!(r.matches(&Url::parse(&sub).unwrap()));
        }
    }
}
