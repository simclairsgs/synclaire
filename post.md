Hi everyone,
After working with Rust on the network and transport layer for a while, I noticed every TCP project starts with the same boilerplate. Accept loop, TLS setup, connection guards, graceful shutdown. So I tried building synclaire to handle that layer once, properly.

You implement a handler with your protocol logic. synclaire runs everything around it. Be it a custom protocol or handle the stream with another protocol framework like warp.

```
use synclaire::{AsyncServer, Connection, ConnectionHandler, ServerConfig, SynError};
use synclaire::handler::HandlerFuture;

struct MyProtocol; // your logic here — HTTP, game protocol, custom binary, anything

impl ConnectionHandler for MyProtocol {
    fn handle<'a>(&'a self, mut conn: Connection) -> HandlerFuture<'a> {
        Box::pin(async move {
            // conn gives you read/write, peer IP, TLS status
            // get underlying stream to process in somewhere else
            // or do whatever your protocol needs
            Ok(())
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), SynError> {
    AsyncServer::new(ServerConfig::default(), MyProtocol).run().await
}
```
### Add TLS
```
ServerConfig::builder()
    .bind_addr("0.0.0.0:443".parse().unwrap())
    .tls(TlsConfig::builder()
        .certificate_chain(PemSource::file("cert.pem"))
        .private_key(PemSource::file("key.pem"))
        .build())
    .build()
```
### Add Guard layer
```
GuardStackConfig {
    rate_limiter: Some(RateLimiterConfig {
        per_ip_capacity: 100,
        per_ip_refill_per_second: 20,
        ..Default::default()
    }),
    syn_guard: Some(SynGuardConfig::default()),
    slow_loris: Some(SlowLorisConfig::default()),
    ip_ban: Some(IpBanConfig {}),
    ..Default::default()
}
```
Stack only what you need — guards compose and roll back cleanly if a later one rejects.

### What's included:

 - Async (Tokio) + Sync — same API shape, feature flagged
 - TLS, mTLS, mixed-mode — TCP and TLS on the same port, auto-detected per connection
 - rustls with ring (default) or aws-lc-rs for FIPS
 - Guard stack — rate limiting, SYN flood, slow loris, throttle, IP ban — memory-bounded against IP rotation attacks
 - Routing + load balancing — round-robin, consistent-hash, runtime-updatable
 - TCP proxy — TLS offload, auth, runtime credential rotation
 - Metrics — per-server, per-IP, real-time callbacks
 - Graceful shutdown on both async and sync
 - TCP/TLS/mTLS with Proxy, Clients

Currently in v0.1.2 — MIT licensed, still early days. I'd love to hear what works, what doesn't, and what's missing before the API hardens. If you build something on it or just have thoughts, drop an issue or a PR — all feedback welcome.

crates.io: https://crates.io/crates/synclaire \
docs: https://docs.rs/synclaire \
GitHub: https://github.com/simclairsgs/synclaire

Thanks for checking this out — hope it's useful to someone out there. 🦀

☮️