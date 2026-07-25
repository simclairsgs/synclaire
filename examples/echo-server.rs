// Echo server — stream inspection + read/write loop.
//   cargo run --example echo-server

use synclaire::{ServerConfig, SynError};

#[cfg(feature = "async")]
use std::time::Duration;
#[cfg(feature = "async")]
use synclaire::{handler::ConnectionHandler, AsyncServer, AsyncStream};
#[cfg(feature = "async")]
use tracing_subscriber::EnvFilter;

struct EchoHandler;

#[cfg(feature = "async")]
impl ConnectionHandler for EchoHandler {
    fn handle<'a>(&'a self, mut connection: synclaire::Connection) -> synclaire::handler::HandlerFuture<'a> {
        Box::pin(async move {
            let tls = connection.is_tls();
            let peer = connection.peer_addr();
            log::info!("new connection peer={} tls={}", peer, tls);

            match connection.async_stream().expect("async connection") {
                AsyncStream::Tcp(tcp) => {
                    let _ = tcp.peer_addr();
                    log::info!("plain TCP connection peer={}", peer);
                }
                AsyncStream::ServerTls(_tls_stream) => {
                    log::info!("TLS connection peer={}", peer);
                }
                AsyncStream::ClientTls(_) => {}
            }

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

#[cfg(all(not(feature = "async"), feature = "sync"))]
impl synclaire::SyncConnectionHandler for EchoHandler {
    fn handle(&self, conn: synclaire::Connection) -> synclaire::error::Result<()> {
        use std::io::{Read, Write};
        let peer = conn.peer_addr();
        let tls = conn.is_tls();
        log::info!("new connection peer={} tls={}", peer, tls);
        let mut stream = conn.into_stream().into_sync().expect("sync stream");
        let mut buf = vec![0_u8; 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => stream.write_all(&buf[..n])?,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut
                       || e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

#[cfg(feature = "async")]
#[tokio::main]
async fn main() -> Result<(), SynError> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("synclaire=info".parse().unwrap()))
        .try_init()
        .ok();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    log::info!("starting echo server on port {}", port);

    let config = ServerConfig::builder()
        .name("echo-server")
        .connection_timeout(Duration::from_secs(60))
        .build();

    AsyncServer::from_listener(listener, config, EchoHandler).run().await
}

#[cfg(all(not(feature = "async"), feature = "sync"))]
fn main() -> Result<(), SynError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    log::info!("starting echo server on port {}", port);

    let config = ServerConfig::builder()
        .name("echo-server")
        .build();
    synclaire::SyncServer::from_listener(listener, config, EchoHandler).run()
}

#[cfg(not(any(feature = "async", feature = "sync")))]
fn main() {
    eprintln!("enable either the async or sync feature");
}