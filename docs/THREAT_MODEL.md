# plugbox security model and threat model

This document says what plugbox defends against, how, and where the
defences stop. It is written for an operator deciding whether to run code
they did not write inside plugbox, and for a reviewer checking the claims.
Every control listed under "Controls" has a test; the test names are given
so you can check them.

## 1. Assets

| asset | why it matters |
|---|---|
| Host process integrity | one process serves every plugin; if it crashes or wedges, every tenant goes down |
| Host secrets | process environment, files readable by the plugbox user, cloud credentials reachable over the network (instance metadata) |
| Internal network | loopback and private services next to the edge node |
| Other plugins' data | KV namespaces, request contents, response bodies |
| Capacity | CPU, memory, pool slots, outbound connections |
| Operator observability | logs and metrics must not be forgeable or floodable |

## 2. Trust boundaries and actors

```
             untrusted                  trusted (operator)
 ┌─────────────────────────┐   ┌───────────────────────────────────────┐
 │ HTTP clients            │──▶│ data plane (hyper)                    │
 │ plugin authors / plugin │   │   └─ runtime ──▶ wasmtime sandbox ◀── guest code
 │   code (the .wasm)      │   │ plugbox.toml, component files,        │
 │ upstream servers        │◀──│ AOT cache dir, admin plane listener   │
 └─────────────────────────┘   └───────────────────────────────────────┘
```

* **Plugin code is untrusted.** The design goal is that a component written
  by an attacker, granted nothing, can at worst waste its own CPU, memory
  and wall-clock budget (`timeout_ms`, whether it spins or blocks) and
  return a bad response for its own route. Each request still holds one
  concurrency permit for up to that budget, so a client flooding one route
  can fill the pool; that is request flooding (T11), not a sandbox escape.
* **HTTP clients are untrusted.** They choose method, path, query, headers
  and body for a plugin.
* **Upstreams are semi-trusted.** They are on the operator's allow-list,
  but their responses are size-limited and parsed defensively.
* **The operator is trusted.** Whoever can edit `plugbox.toml`, replace
  component files, write to the AOT cache directory or reach the admin
  listener controls plugbox completely. These are not attack surfaces in
  this model; protect them with file permissions and network placement.

## 3. Controls

### 3.1 Isolation of guest code

* Guests run as WebAssembly components inside wasmtime (pinned to
  `=50.0.0`). Linear memory is bounds-checked; guests cannot address host
  memory, call host functions that were not linked, or forge pointers.
* **One instance per request.** Each request gets a fresh `Store` and a
  fresh instance (`src/runtime.rs::invoke`). Nothing in linear memory
  survives the request, so a guest cannot read the previous request's data
  and a trapped instance is never re-entered.
  Test: `pooling::instances_never_share_state_between_requests`.
* **Import policy at load time** (`src/policy.rs`). A component may only
  import `plugbox:host/*` and the inert WASI interfaces a `wasm32-wasip2`
  program needs (`wasi:io`, `wasi:clocks`, `wasi:random`, `wasi:cli`,
  `wasi:filesystem`). Anything else, notably `wasi:sockets` and `wasi:http`,
  rejects the component before any code runs. A missing
  `plugbox:host/handler` export is also rejected.
  Tests: `policy::raw_socket_plugin_is_rejected_at_load_time` (the `sneaky`
  fixture really calls `TcpStream::connect`),
  `policy::registry_refuses_to_start_with_a_rejected_plugin`,
  `policy::a_component_without_the_handler_export_is_rejected`.
* **Locked-down WASI** (`src/host.rs::HostState::new`). No arguments, an
  empty environment, no preopened directories (every filesystem call
  fails), TCP/UDP/name lookup disabled even at the context level, stdin
  empty, stdout and stderr captured into a capped buffer.
  Test: `limits::ungranted_env_files_and_kv_are_invisible` (reads
  `AWS_SECRET_ACCESS_KEY`, iterates `std::env::vars()`, opens
  `/etc/passwd`).

### 3.2 Resource limits

| limit | mechanism | result | test |
|---|---|---|---|
| CPU, deterministic | wasmtime fuel, `limits.fuel` per request | trap, `504 fuel-exhausted` | `limits::infinite_loop_trips_fuel` |
| CPU, wall clock | epoch interruption: ticker thread every `epoch_tick_ms`, deadline `ceil(timeout/tick)+1` ticks | trap, `504 deadline-exceeded` | `limits::infinite_loop_trips_epoch_deadline_without_fuel` |
| wall clock while blocked in WASI | deadline-capped `wasi:clocks/monotonic-clock` (`src/clock.rs`): every clock pollable fires no later than the request deadline, and a wait the deadline cut short becomes a trap | `504 deadline-exceeded` at the deadline, thread and permit released | `limits::blocking_sleep_is_cut_at_the_deadline`, `limits::concurrent_sleepers_release_their_threads_at_the_deadline`, `server::sleeping_plugins_release_their_permits_at_the_deadline`, `clock::tests::*` |
| memory | `ResourceLimiter` over *all* memories of the component, plus `max_memory_size` on the pool | growth refused, guest aborts, `502 memory-limit` | `limits::memory_bomb_trips_memory_limit` |
| native stack | `max_wasm_stack = 1 MiB` | trap, `502 stack-overflow` | `limits::unbounded_recursion_trips_stack_limit` |
| shadow stack | lives in linear memory, so overflow is an out-of-bounds access | trap, `502 memory-fault` | `limits::shadow_stack_overflow_is_a_contained_memory_fault` |
| tables / instances / memories | limiter caps (`src/limits.rs`) | instantiation refused | `limits::tests::table_and_count_limits` |
| concurrency | semaphore (`max_concurrency`) and the pool size | immediate `503 overloaded`, never an unbounded queue | `server::excess_concurrency_is_shed`, `pooling::exhausted_pool_sheds_instead_of_blocking` |
| request body | `Limited` body collector | `413` before the sandbox is touched | `server::oversized_bodies_are_rejected_before_the_sandbox` |
| response body / headers | validated after the call | `502 invalid-response` (no header injection) | `limits::oversized_response_is_replaced`, `runtime::tests::response_validation` |
| logs and stdout | per-request line cap, 1 KiB message truncation, control characters escaped, capped stdio buffer that discards instead of erroring | dropped and counted | `limits::log_and_stdout_floods_are_capped`, `host::tests::control_characters_are_escaped` |
| slow clients | hyper `header_read_timeout` 10 s | connection closed | (configuration, not separately tested) |

Fuel and epochs are both always enabled engine-wide. Setting
`limits.fuel = 0` disables only fuel for that plugin; the wall-clock
deadline still applies. Fuel and epochs are only checked while wasm code
runs, so neither can interrupt a host call, and every host call is bounded
on its own:

* outbound HTTP timeouts are capped by the request's *remaining* budget;
* KV operations are in-memory map operations bounded by the quotas;
* **blocking WASI calls.** The only WASI pollables a plugbox guest can block
  on are monotonic-clock subscriptions (`std::thread::sleep`, `poll` with a
  timeout): sockets are refused at load, nothing is preopened, stdin is
  empty and stdout/stderr are in-memory. Stock wasmtime-wasi would block the
  host thread for as long as the guest asks, holding a `spawn_blocking`
  thread and one server-wide concurrency permit, so ~`max_concurrency`
  sleeping requests to one plugin would make every plugin answer `503`.
  plugbox therefore shadows the four `wasi:clocks/monotonic-clock`
  functions (`src/clock.rs`, linked in `host::add_to_linker`). Each
  `subscribe-duration` / `subscribe-instant` pollable is capped at the
  request deadline; if the deadline is what ended the wait, the request is
  reported as `504 deadline-exceeded` even if the guest returns a response
  before the next epoch check. Measured with a guest that sleeps 2 s under
  `timeout_ms = 50, fuel = 1_000_000`: 2.003 s before the fix, 53 ms after.
  If a future change links another pollable that can block (sockets,
  `wasi:http`, a real stdin), it must be capped the same way.

**The host stays healthy.** After every limit trips, the tests check that a
well-behaved plugin still answers, `in_flight` is back to 0 and the pool has
no live instances (`limits.rs::Env::assert_healthy`). Two tests stress it:
`limits::host_stays_healthy_under_concurrent_abuse` (concurrent loops, bombs,
panics and good requests) and
`limits::many_sequential_traps_do_not_leak_pool_slots`.

### 3.3 Capabilities

Deny by default, deny without trapping: an ungranted call returns a typed
error (`none`, `not-granted`, `forbidden`), increments
`plugbox_capability_denials_total{plugin,capability}`, and the request goes
on. Grants are resolved once per (re)load into `Capabilities`
(`src/capability/mod.rs`) and checked on every call.

* **env**: the plugin sees exactly `grants.env.vars` plus the names listed
  in `grants.env.inherit` (copied from the host at load time). Never the
  host environment. Test: `capabilities::env_grants_are_exact`.
* **kv**: one in-process store partitioned by namespace. A plugin reaches
  only the namespace in its grant (default: its own name). An implicit
  namespace is private: another plugin naming it is a config error;
  sharing requires both plugins to name the namespace explicitly. Read-only
  grants, key-count and value-size quotas, key validation (no empty, over-long
  or control-character keys). Tests: `capabilities::kv_state_persists_across_fresh_instances`,
  `capabilities::kv_quota_surfaces_as_a_guest_error`,
  `config::tests::rejects_semantic_errors`, `capability::kv::tests::*`.
* **outbound HTTP**: one enforcement point, `Outbound::fetch`
  (`src/outbound.rs`), in this order:
  1. a grant must exist;
  2. the per-request call budget is charged (`max_requests`);
  3. the URL is parsed by a deliberately strict parser
     (`src/allowlist.rs`) that *rejects* rather than normalises known
     allow-list bypasses: userinfo (`http://allowed@evil/`), percent-escapes,
     backslashes or whitespace in the authority, non-canonical numeric hosts
     (`http://2130706433/`, `http://0x7f.1/`, `http://127.1/`), dot segments
     in the path including encoded ones (`/api/%2e%2e/admin`);
  4. the URL must match an allow rule (scheme, host or `*.` suffix, port,
     path prefix);
  5. method and header names must be tokens, values must not contain
     CR/LF/NUL, hop-by-hop headers are dropped;
  6. the host is resolved **once** and the address policy is applied to
     *every* resolved address: link-local (including `169.254.169.254`
     cloud metadata), unspecified, multicast and broadcast are always
     refused; loopback, RFC 1918, CGNAT and ULA are refused for hostname
     rules unless `allow_private = true`. IPv4-mapped IPv6 is unwrapped
     first. IP-literal rules are trusted as written;
  7. the client connects only to the vetted addresses (it never resolves
     again, which closes the DNS-rebinding window between check and use);
  8. timeout = min(grant timeout, remaining request budget); the response
     body is capped at `max_response`.

  Tests: `limits::forbidden_host_is_refused_without_trapping`,
  `limits::outbound_call_budget_is_enforced`,
  `capabilities::outbound_http_reaches_only_allowed_upstreams`, and the
  property tests: in `allowlist.rs`, arbitrary input never panics the URL or
  rule parser, generated URLs round-trip through `Display`, userinfo is
  always rejected, and `*.example.com` never matches a look-alike apex such
  as `evilexample.com`; in `outbound.rs`, arbitrary bytes never panic the
  HTTP response parser and chunked bodies decode exactly.

### 3.4 Hot reload

A reload builds a complete new snapshot, then swaps one pointer. If any
plugin fails to read, compile, pass the import policy, link, or bind its
grants, the old snapshot keeps serving and the error is exposed on
`/health` and in `plugbox_reloads_total{result="error"}`. In-flight
requests finish on the version they started with. The file watcher waits
for a file's (mtime, size) to be stable for one poll interval so a
half-written component is not loaded. Tests: `reload::*`.

### 3.5 AOT cache

With `runtime.cache_dir` set, compiled artifacts are written there and
loaded with `Component::deserialize_file`, which is `unsafe`: wasmtime
trusts serialized artifacts to contain machine code it produced.
Mitigations: files are keyed by the component's SHA-256 and the engine's
compatibility hash, written atomically, and wasmtime validates the header.
**These do not make the cache safe against a writer.** Anyone who can write
the cache directory can run native code in the plugbox process. The
directory must be owned by and writable only by the plugbox user. The cache
is off by default.

A loaded artifact stays memory-mapped for as long as its component is in
use, and wasmtime requires the file to stay unchanged for that whole time.
plugbox only ever replaces an entry by writing a temporary file and
renaming it over the old one, which leaves existing mappings intact.
Rewriting a cache file *in place* (copying over it, truncating it) while
plugbox runs corrupts the components loaded from it: on macOS the next
instance faults with an out-of-bounds trap, on Linux the process dies with
`SIGBUS`. To clear the cache, delete the files or the directory; never edit
them. Test: `pooling::aot_cache_is_written_and_reused` (a damaged entry
found at startup is discarded and rebuilt).

## 4. Threats and status

| # | threat | status |
|---|---|---|
| T1 | Plugin burns CPU or wall-clock time forever (busy loop, or blocking in `wasi:io/poll`) | mitigated: fuel + epoch deadline for running wasm; deadline-capped monotonic clock for blocked waits (§3.2) |
| T2 | Plugin exhausts host memory | mitigated: per-instance limiter, pool `max_memory_size`, pool size bounds the total |
| T3 | Plugin crashes the host (panic, stack overflow) | mitigated: traps are values; guest stack overflows are caught by wasmtime |
| T4 | Plugin reads host secrets (env, files) | mitigated: inert WASI, explicit env grants |
| T5 | SSRF to metadata / internal services | mitigated: strict parser, allow-list, post-resolution address policy, no re-resolution |
| T6 | Plugin opens raw sockets | mitigated: `wasi:sockets` never linked, import policy rejects at load |
| T7 | Cross-request / cross-tenant data leak through memory | mitigated: one instance per request |
| T8 | Cross-plugin data leak through KV | mitigated: namespaces; implicit namespaces private |
| T9 | Header / response splitting via plugin output | mitigated: response validation |
| T10 | Log forging / flooding | mitigated: escaping, truncation, line caps |
| T11 | Request flood / slow-loris | partly mitigated: concurrency shedding, header timeout, body limit. No per-client rate limiting |
| T12 | Spectre-class side channels between plugins in one process | **not mitigated** beyond what wasmtime does by default. Do not co-host mutually hostile tenants that hold secrets worth a side-channel attack |
| T13 | Bugs in wasmtime / cranelift | **accepted**: pinned version, must be upgraded when advisories land |
| T14 | Malicious operator, writable config, writable AOT cache, exposed admin plane | **out of scope**; the admin plane has no authentication and must stay on loopback or a private network |
| T15 | Upstream returns hostile data | partly mitigated: head and body size limits, strict status-line parsing; the plugin still receives whatever bytes the upstream sends |
| T16 | Outbound traffic interception | **not mitigated**: the built-in client speaks plain HTTP only; `https://` rules are parsed but calls fail with a transport error |

## 5. Ethics and scope

The `hostile` and `sneaky` plugins are benign test fixtures. Every
"attack" they make targets the plugbox sandbox itself: the metadata address
is refused before any packet is sent, and the raw-socket attempt is refused
before the component is instantiated. The demo and tests talk only to
upstream servers they start on `127.0.0.1`.
