<div align="center">

# synclaire

**TCP/TLS transport library for Rust — guards, routing, load balancing, and proxy built in.**

[![Crates.io](https://img.shields.io/crates/v/synclaire.svg)](https://crates.io/crates/synclaire)
[![docs.rs](https://docs.rs/synclaire/badge.svg)](https://docs.rs/synclaire)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Docs](https://docs.rs/synclaire) | [Crate](https://crates.io/crates/synclaire) | [Examples](examples/)

</div>

synclaire sits between raw sockets and application protocols. You write a handler, synclaire runs the accept loop, manages TLS, enforces connection guards, and routes traffic — so you ship protocol logic, not plumbing. Includes both Client and Server APIs.

```
  your app
    |
 synclaire --- guards ─── TLS ─── routing ─── proxy --->  handler
    |
  TCP/TLS
```

### What's included

| | |
|---|---|
| **Async + Sync servers & clients** | Tokio-based async or threaded sync — same API shape |
| **TLS, mTLS, mixed-mode** | rustls with ring or aws-lc-rs (FIPS); auto-detect TLS vs plain TCP per connection |
| **Guard stack** | Rate limiter, SYN flood, slow loris, throttle, IP ban — layered, rollback-safe |
| **Routing & load balancing** | IP-based rules, round-robin and consistent-hash pools, runtime-updatable |
| **TCP proxy** | Auth, TLS offload, credential rotation, pluggable routing |
| **Metrics** | Per-server, per-IP counters with real-time callbacks |

---

## Quick start

```toml
[dependencies]
synclaire = "0.1"
```

### Async echo server

```rust
use synclaire::{AsyncServer, ConnectionHandler, ServerConfig};

struct Echo;

impl ConnectionHandler for Echo {
    fn handle<'a>(
        &'a self,
        mut conn: synclaire::Connection,
    ) -> synclaire::handler::HandlerFuture<'a> {
        Box::pin(async move {
            let mut buf = [0u8; 1024];
            loop {
                let n = conn.read(&mut buf).await?;
                if n == 0 { break; }
                conn.write_all(&buf[..n]).await?;
            }
            Ok(())
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), synclaire::SynError> {
    let config = ServerConfig::builder()
        .bind_addr("0.0.0.0:4000".parse().unwrap())
        .build();
    AsyncServer::new(config, Echo).run().await
}
```

### Sync echo server

```rust
use std::io::{Read, Write};
use synclaire::{SyncServer, SyncConnectionHandler, ServerConfig, Connection, SynError};

struct Echo;

impl SyncConnectionHandler for Echo {
    fn handle(&self, conn: Connection) -> Result<(), SynError> {
        let mut stream = conn.into_stream().into_sync().expect("sync stream");
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => stream.write_all(&buf[..n])?,
            }
        }
        Ok(())
    }
}

fn main() -> Result<(), SynError> {
    let config = ServerConfig::builder()
        .bind_addr("0.0.0.0:4000".parse().unwrap())
        .build();
    SyncServer::new(config, Echo).run()
}
```

## Graceful shutdown

Both async and sync servers support graceful shutdown via a channel:

```rust
let (shutdown, signal) = AsyncServer::<Echo>::shutdown_channel();
tokio::spawn(async move { server.run_until_shutdown(signal).await.ok(); });
// later...
shutdown.shutdown()?;
```

`SyncServer` has the same API (`shutdown_channel()` + `run_until_shutdown()`).

## Guard stack

Built-in connection guards that run before your handler sees the connection. Stack them to create layered transport defense:

```rust
use synclaire::GuardStackConfig;
use synclaire::guard::*;
use std::time::Duration;

let guards = GuardStackConfig {
    rate_limiter: Some(RateLimiterConfig {
        per_ip_capacity: 100,
        per_ip_refill_per_second: 20,
        global_capacity: 1_000,
        global_refill_per_second: 200,
        global_window: Duration::from_secs(10),
        global_window_limit: 5_000,
        max_tracked_ips: 100_000,
    }),
    throttle: Some(ThrottleConfig {
        max_connections_per_ip: 10,
        max_connections_global: 50_000,
    }),
    syn_guard: Some(SynGuardConfig {
        max_half_open_per_ip: 5,
        max_half_open_global: 10_000,
        backlog_limit: 1_024,
        syn_timeout: Duration::from_secs(5),
        max_tracked_ips: 100_000,
    }),
    slow_loris: Some(SlowLorisConfig {
        idle_timeout: Duration::from_secs(10),
        grace_period: Duration::from_secs(3),
        max_tracked_connections: 100_000,
    }),
    ip_ban: Some(IpBanConfig {}),
    ..Default::default()
};
```

| Guard | What it does |
|-------|-------------|
| **RateLimiter** | Token-bucket rate limiting per IP |
| **Throttle** | Caps concurrent connections per IP and globally |
| **SynGuard** | Limits half-open connections to mitigate SYN floods |
| **SlowLoris** | Drops connections that go idle too long |
| **IpBan** | Runtime-mutable IP blocklist with `ban()`/`unban()` API |

Guards implement a lifecycle (`on_reserve` / `on_established` / `on_payload` / `on_activity` / `on_close`) and are automatically rolled back if a later guard in the stack rejects. All per-IP tracking maps are bounded to prevent memory exhaustion under IP rotation attacks.

**Allowlist** — trusted IPs skip the entire guard chain. Runtime-mutable via `allow()`/`remove()`:

```rust
let guards = GuardStack::builder()
    .push(RateLimiter::new(limiter_config))
    .build();

// At any time, from any thread:
guards.allowlist().allow("10.0.0.1".parse().unwrap());
guards.allowlist().remove(&"10.0.0.1".parse().unwrap());
```

## TLS

TLS is handled by rustls. System root certificates are loaded by default.

```rust
use synclaire::config::{TlsConfig, PemSource, AcceptMode, ServerConfig};

let tls = TlsConfig::builder()
    .enabled(true)
    .certificate_chain(PemSource::file("cert.pem"))
    .private_key(PemSource::file("key.pem"))
    .build();

let config = ServerConfig::builder()
    .tls(tls)
    .accept_mode(AcceptMode::Tls)
    .build();
```

**Mixed mode** — `AcceptMode::Mixed` auto-detects whether each incoming connection is TLS or plain TCP on the same port. Use `connection.is_tls()` in the handler to branch.

**mTLS** — set `.require_client_auth(true)` on the server's `TlsConfig` and provide `.trust_anchor(...)` with the client CA.

Client-side:

```rust
let tls = TlsConfig::builder()
    .enabled(true)
    .server_name("example.com")
    .build(); // uses system root CAs by default

let config = ClientConfig::builder()
    .connect_addr("example.com:443".parse().unwrap())
    .tls(tls)
    .build();
```

## Routing and load balancing

Route connections to different backends based on source IP, with pluggable load balancing:

```rust
use std::sync::Arc;
use synclaire::{RoutingTable, RoutingRule, RouteAction, IpGroup, IpPrefix, BackendPool};

let pool = Arc::new(BackendPool::round_robin([
    "10.0.0.1:8080".parse().unwrap(),
    "10.0.0.2:8080".parse().unwrap(),
]));

let routing = Arc::new(RoutingTable::new(RouteAction::Reject));
routing.add_group("internal", IpGroup::new().add_prefix(IpPrefix::v4(10, 0, 0, 0, 8)));
routing.add_rule(
    RoutingRule::new("internal-to-pool", RouteAction::Pool(pool)).from_group("internal"),
);
```

Pool strategies: `round_robin`, `consistent_hash` (with `StickyKey::Ip` for session affinity and weighted backends).

## Proxy

TCP proxy with optional auth, routing, guards, and TLS offload:

```rust
use synclaire::{ProxyConfig, ProxyServer, ProxyAuth};

let config = ProxyConfig::new("0.0.0.0:8080".parse()?, "10.0.0.1:3000".parse()?)
    .with_auth(ProxyAuth::basic("user", "pass"))
    .with_buffer_size(8192);

ProxyServer::new(config).run()?;
```

Both sync (`ProxyServer`) and async (`AsyncProxyServer`) variants available.

**Dynamic auth rotation** — use `ProxyAuthHandle` to rotate credentials at runtime without restarting the proxy:

```rust
let auth_handle = ProxyAuthHandle::new(ProxyAuth::basic("admin", "secret"));
let server = ProxyServer::new(config).with_auth_handle(auth_handle.clone());
// later, from another thread:
auth_handle.set_basic("admin", "new-secret")?;
```

**TLS offload** (async only) — terminate TLS at the proxy, forward plaintext to the backend:

```rust
let tls = TlsConfig::builder()
    .enabled(true)
    .certificate_chain(PemSource::file("proxy.crt"))
    .private_key(PemSource::file("proxy.key"))
    .build();

let config = ProxyConfig::new(listen_addr, backend_addr)
    .with_tls_offload(tls);

AsyncProxyServer::new(config).run().await?;
```

## Metrics

```rust
use std::sync::Arc;
use synclaire::metrics::MetricsCollector;

let metrics = Arc::new(MetricsCollector::new());
// Pass to proxy via .with_metrics(metrics.clone())

let snapshot = metrics.snapshot();
println!("Active: {}, TCP: {}, TLS: {}", 
    snapshot.active_connections, snapshot.tcp_connections_total, snapshot.tls_connections_total);
```

Per-server, per-IP breakdowns and real-time callbacks via `MetricsCallback` trait.

## Connection filters

Composable filters for custom accept/reject logic per connection:

```rust
use std::sync::Arc;
use synclaire::connection_filter::*;

let filter = CompositeFilter::new()
    .add_filter(Arc::new(IpBlocklistFilter::new(["10.0.0.1".parse().unwrap()])))
    .add_filter(Arc::new(TlsOnlyFilter));
```

Implement the `ConnectionFilter` trait for custom auth — `filter(&self, conn: &Connection) -> Result<(), SynError>`.

## Feature flags

| Flag | Default | What it enables |
|------|---------|----------------|
| `async` | yes | Tokio-based async server/client (`AsyncServer`, `AsyncClient`) |
| `sync` | no | Sync server/client (`SyncServer`, `SyncClient`) |
| `rustls-backend` | yes | TLS via rustls + ring (pure Rust, no C compiler) |
| `aws-lc-backend` | no | TLS via rustls + aws-lc-rs (FIPS-capable, requires cmake) |
| `full` | no | `async` + `sync` + `rustls-backend` |

```toml
# Async only (default — uses ring crypto provider)
synclaire = "0.1"

# Sync only
synclaire = { version = "0.1", default-features = false, features = ["sync", "rustls-backend"] }

# FIPS-capable TLS (aws-lc-rs instead of ring)
synclaire = { version = "0.1", default-features = false, features = ["async", "aws-lc-backend"] }

# Both async + sync
synclaire = { version = "0.1", features = ["full"] }
```

## Examples

```bash
# Async TCP echo (server + client demo)
cargo run --example tcp-client-server-async

# Sync TCP echo
cargo run --example tcp-client-server-sync --features sync

# Standalone server / client
cargo run --example echo-server
cargo run --example basic-client

# Guard API demo
cargo run --example guard-api

# Metrics API demo
cargo run --example metrics-api

# Proxy with routing + auth
cargo run --example proxy-usage --features sync

# TLS examples require certificates — generate them first:
cd examples && sh generate-certs.sh && cd ..

cargo run --example tls-client-server-async
cargo run --example tls-client-server-sync --features "sync,rustls-backend"
cargo run --example tls-server

# Mixed-mode (TCP + TLS on same port)
cargo run --example mixed-client-server-async
cargo run --example mixed-client-server-sync --features "sync,rustls-backend"

# Mutual TLS (mTLS)
cargo run --example mtls-client-server-async
cargo run --example mtls-client-server-sync --features "sync,rustls-backend"
```

## License

MIT
