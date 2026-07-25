use std::time::Duration;

use synclaire::{handler::ConnectionHandler, AsyncServer, AsyncStream, ServerConfig, SynError};
use tracing_subscriber::EnvFilter;

struct EchoHandler;

impl ConnectionHandler for EchoHandler {
    fn handle<'a>(&'a self, mut connection: synclaire::Connection) -> synclaire::handler::HandlerFuture<'a> {
        Box::pin(async move {
            // You get the concrete stream type directly — no trait-object gymnastics.
            let tls = connection.is_tls();
            let peer = connection.peer_addr();
            log::info!("new connection peer={} tls={}", peer, tls);

            // Pattern-match to get the raw socket if you need it.
            match connection.async_stream().expect("async connection") {
                AsyncStream::Tcp(tcp) => {
                    // Direct access to the TcpStream — set options, inspect peer, etc.
                    let _ = tcp.peer_addr();
                    log::info!("plain TCP connection peer={}", peer);
                }
                AsyncStream::ServerTls(_tls_stream) => {
                    // Direct access to the TLS stream, including get_ref() for the handshake data.
                    log::info!("TLS connection peer={}", peer);
                }
                AsyncStream::ClientTls(_) => {}
            }

            // Or just use the convenience read/write helpers.
            let mut buffer = vec![0_u8; 1024];
            loop {
                let read = connection.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                connection.write_all(&buffer[..read]).await?;
            }

            connection.shutdown().await?;
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

    let config = ServerConfig::builder()
        .name("echo-server")
        .connection_timeout(Duration::from_secs(60))
        .build();

    log::info!("starting echo server bind={}", config.bind_addr);
    AsyncServer::new(config, EchoHandler).run().await
}

#[cfg(all(not(feature = "async"), feature = "sync"))]
fn main() -> Result<(), SynError> {
    let config = ServerConfig::builder().name("echo-server").build();
    let server = synclaire::SyncServer::new(config, EchoHandler);
    server.run()
}

#[cfg(not(any(feature = "async", feature = "sync")))]
fn main() {
    eprintln!("enable either the async or sync feature");
}