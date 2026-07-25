# synclaire

[![Crates.io](https://img.shields.io/crates/v/synclaire.svg)](https://crates.io/crates/synclaire)
[![docs.rs](https://docs.rs/synclaire/badge.svg)](https://docs.rs/synclaire)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Transport-layer TCP/TLS library for Rust with built-in connection guards, routing, and proxy primitives.

synclaire sits between raw sockets and application protocols. It handles TCP/TLS streams, connection lifecycle, and transport-level defense so your application layer can focus on protocol logic.

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

## Guard stack

Built-in connection guards that run before your handler sees the connection. Stack them to create layered transport defense:

```rust
use synclaire::config::GuardStackConfig;
use synclaire::guard::*;
use std::time::Duration;

let guards = GuardStackConfig {
    rate_limiter: Some(RateLimiterConfig {
        max_per_ip: 100,
        refill_interval: Duration::from_secs(1),
        max_tracked_ips: 100_000,
    }),
    throttle: Some(ThrottleConfig {
        max_connections_per_ip: 10,
        max_connections_global: 50_000,
    }),
    syn_guard: Some(SynGuardConfig {
        max_half_open_per_ip: 5,
        max_half_open_total: 10_000,
        syn_timeout: Duration::from_secs(5),
        max_tracked_ips: 100_000,
    }),
    slow_loris: Some(SlowLorisConfig {
        idle_timeout: Duration::from_secs(10),
        max_tracked_connections: 100_000,
    }),
    ip_ban: Some(IpBanConfig {}),
    ..Default::default()
};

let config = ServerConfig::builder()
    .guards(guards)
    .build();
```

| Guard | What it does |
|-------|-------------|
| **RateLimiter** | Token-bucket rate limiting per IP |
| **Throttle** | Caps concurrent connections per IP and globally |
| **SynGuard** | Limits half-open connections to mitigate SYN floods |
| **SlowLoris** | Drops connections that go idle too long |
| **IpBan** | Runtime-mutable IP blocklist with `ban()`/`unban()` API |

Guards implement a lifecycle (`on_reserve` / `on_established` / `on_activity` / `on_close`) and are automatically rolled back if a later guard in the stack rejects. All per-IP tracking maps are bounded to prevent memory exhaustion under IP rotation attacks.

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
    .accept_mode(AcceptMode::Tls)  // or AcceptMode::Mixed for auto-detect
    .build();
```

Client-side:

```rust
use synclaire::{AsyncClient, ClientConfig};
use synclaire::config::{TlsConfig, PemSource};

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

Route connections to different backends based on IP rules:

```rust
use synclaire::routing::*;
use synclaire::load_balancer::*;

let pool = BackendPool::new(
    vec![
        Backend::new("10.0.0.1:8080".parse().unwrap()),
        Backend::new("10.0.0.2:8080".parse().unwrap()),
    ],
    LoadBalancerStrategy::RoundRobin,
);

let table = RoutingTable::new(vec![
    RoutingRule::new(
        IpGroup::prefix("192.168.0.0/16".parse().unwrap()),
        RouteAction::Pool(pool),
    ),
]);
```

Load balancer strategies: `RoundRobin`, `Random`, `LeastConnections`, `ConsistentHash`.

## Proxy

TCP proxy with optional HTTP CONNECT auth:

```rust
use synclaire::proxy::{ProxyConfig, ProxyServer, ProxyAuth};

let config = ProxyConfig {
    listen_addr: "0.0.0.0:8080".parse().unwrap(),
    backend_addr: "10.0.0.1:3000".parse().unwrap(),
    auth: Some(ProxyAuth::basic("user", "pass")),
    ..Default::default()
};

ProxyServer::new(config).run()?;
```

Both sync (`ProxyServer`) and async (`AsyncProxyServer`) variants available.

## Metrics

```rust
use synclaire::metrics::{MetricsCollector, LoggingMetricsCallback};

let metrics = MetricsCollector::new()
    .with_callback(LoggingMetricsCallback);

// After connections flow through:
let snapshot = metrics.snapshot();
println!("Active: {}", snapshot.active_connections);
println!("Total: {}", snapshot.total_connections);
```

## Connection filters

Composable filters applied before the guard stack:

```rust
use synclaire::connection_filter::*;

let filter = CompositeFilter::new(vec![
    Box::new(IpBlocklistFilter::new(vec!["10.0.0.1".parse().unwrap()])),
    Box::new(TlsOnlyFilter),
]);
```

## Feature flags

| Flag | Default | What it enables |
|------|---------|----------------|
| `async` | yes | Tokio-based async server/client (`AsyncServer`, `AsyncClient`) |
| `sync` | no | Sync server/client (`SyncServer`, `SyncClient`) |
| `rustls-backend` | yes | TLS via rustls with system root certificates |
| `full` | no | All of the above |

```toml
# Async only (default)
synclaire = "0.1"

# Sync only
synclaire = { version = "0.1", default-features = false, features = ["sync", "rustls-backend"] }

# Both
synclaire = { version = "0.1", features = ["full"] }
```

## Examples

```bash
# Async TCP echo (server + client demo)
cargo run --example tcp-client-server-async

# Sync TCP echo
cargo run --example tcp-client-server-sync --features sync

# TLS server
cargo run --example tls-client-server-async

# Mutual TLS
cargo run --example mtls-client-server-async

# Proxy with routing
cargo run --example proxy-usage --features sync

# Guard API demo
cargo run --example guard-api
```

## License

MIT
