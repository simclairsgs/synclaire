# synclaire

Where every connection is handled with clarity.

synclaire is a Rust transport-layer library for TCP and TLS networking. It is designed for applications that want direct stream control with optional defense, routing, and proxy utilities.

## Why synclaire

- Small transport-layer API surface for TCP and TLS workloads
- Runtime flexibility with async and sync modes
- Built-in protective guard stack and routing/proxy primitives
- Easy composition with higher-level protocol frameworks

## What synclaire is

- A transport-layer foundation for raw stream handling
- Usable directly or under higher-level protocol/application stacks
- Runtime-flexible through feature flags (`async` and `sync`)

## Scope

synclaire handles transport concerns only. Application protocol behavior (HTTP, gRPC, etc.) is expected to live in your app or other framework layer.

## Current capabilities

- TCP and TLS client/server transport primitives
- Connection abstractions for async and sync stream handling
- Guard stack:
  - rate limiting
  - IP banning
  - throttling
  - SYN defense
  - slow-loris mitigation
- Routing primitives with IP groups/prefixes and route actions
- Connection filtering (allow/block lists, TLS-only, composition)
- Proxy components for client/server forwarding workflows
- Load balancer primitives (pool, strategy, sticky keys)
- Metrics and cleanup utilities for connection lifecycle management

## Installation

```toml
[dependencies]
synclaire = "0.1"
```

Or choose explicit features:

```toml
[dependencies]
synclaire = { version = "0.1", default-features = false, features = ["async", "rustls-backend"] }
```

## Feature flags

- `default`: `async`, `rustls-backend`
- `async`: enables Tokio-based runtime integration
- `sync`: enables sync runtime support
- `rustls-backend`: enables rustls backend
- `aws-lc-backend`: enables aws-lc-rs backend support
- `full`: enables `async`, `sync`, `rustls-backend`, `aws-lc-backend`

## Minimal async echo server

```rust
use synclaire::{AsyncServer, ConnectionHandler, ServerConfig};

struct Echo;

impl ConnectionHandler for Echo {
    fn handle<'a>(&'a self, mut connection: synclaire::Connection) -> synclaire::handler::HandlerFuture<'a> {
        Box::pin(async move {
            let mut buf = [0_u8; 1024];
            loop {
                let n = connection.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                connection.write_all(&buf[..n]).await?;
            }
            Ok(())
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), synclaire::SynError> {
    AsyncServer::new(ServerConfig::default(), Echo).run().await
}
```

## Examples

```bash
cargo run --example echo_server
cargo run --example tls_server
cargo run --example basic_client
```

## Security model

synclaire provides transport-focused defensive building blocks such as rate limiting, IP banning, throttling, SYN protection, and slow-loris mitigation. Application-layer authentication and authorization remain the responsibility of your protocol/application stack.

## Compatibility

- Rust edition: 2021
- Default feature set: async runtime with rustls backend
- TLS backends: rustls by default, optional aws-lc-rs

## License

MIT

## Project status

Use the repository tests and examples as validation targets during integration:

```bash
cargo test --all-features
cargo check --all-features --examples
```