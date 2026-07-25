//! TLS echo server.
//!
//! This example demonstrates three configurations:
//!   - `AcceptMode::Tls`   — TLS only (default here).
//!   - `AcceptMode::Mixed` — auto-detect per connection (uncomment to try it).
//!
//! Generate self-signed certs for testing:
//!   openssl req -x509 -newkey rsa:4096 -keyout examples/certs/server.key \
//!               -out examples/certs/server.crt -days 365 -nodes -subj '/CN=localhost'

use std::time::Duration;

use synclaire::{
    handler::ConnectionHandler, AcceptMode, AsyncServer, PemSource, ServerConfig,
    SynError, TlsConfig,
};
use tracing_subscriber::EnvFilter;

struct TlsEchoHandler;

impl ConnectionHandler for TlsEchoHandler {
    fn handle<'a>(&'a self, mut connection: synclaire::Connection) -> synclaire::handler::HandlerFuture<'a> {
        Box::pin(async move {
            let peer = connection.peer_addr();

            // is_tls() works regardless of AcceptMode — it reflects what actually happened.
            if connection.is_tls() {
                // Get the concrete server-side TLS stream — includes the rustls session.
                if let Some(tls_stream) = connection.async_stream().as_server_tls() {
                    let (_, session) = tls_stream.get_ref();
                    let protocol = session.alpn_protocol().map(String::from_utf8_lossy);
                    log::info!("TLS handshake complete peer={} alpn={:?}", peer, protocol);
                }
            } else {
                // In Mixed mode this branch serves plain TCP clients.
                log::info!("plain TCP connection on mixed-mode server peer={}", peer);
            }

            let mut buffer = vec![0_u8; 1024];
            loop {
                let read = connection.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                connection.write_all(&buffer[..read]).await?;
            }

            Ok(())
        })
    }
}

#[cfg(feature = "async")]
#[tokio::main]
async fn main() -> Result<(), SynError> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("synclaire=info".parse().unwrap()))
        .try_init()
        .ok();

    let tls = TlsConfig::builder()
        .enabled(true)
        .server_name("localhost")
        .certificate_chain(PemSource::file("examples/certs/server.crt"))
        .private_key(PemSource::file("examples/certs/server.key"))
        .build();

    let config = ServerConfig::builder()
        .name("tls-echo-server")
        .connection_timeout(Duration::from_secs(60))
        .tls(tls)
        // Switch to AcceptMode::Mixed to also accept plain TCP on the same port:
        .accept_mode(AcceptMode::Tls)
        .build();

    log::info!("starting TLS echo server bind={}", config.bind_addr);
    AsyncServer::new(config, TlsEchoHandler).run().await
}

#[cfg(all(not(feature = "async"), feature = "sync"))]
fn main() -> Result<(), SynError> {
    let tls = TlsConfig::builder()
        .enabled(true)
        .server_name("localhost")
        .certificate_chain(PemSource::file("examples/certs/server.crt"))
        .private_key(PemSource::file("examples/certs/server.key"))
        .build();

    let config = ServerConfig::builder().name("tls-echo-server").tls(tls).build();
    synclaire::SyncServer::new(config, TlsEchoHandler).run()
}

#[cfg(not(any(feature = "async", feature = "sync")))]
fn main() {
    eprintln!("enable either the async or sync feature");
}