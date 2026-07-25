// TLS echo server with ALPN inspection.
//   cd examples && sh generate-certs.sh && cd ..
//   cargo run --example tls-server

use synclaire::{PemSource, ServerConfig, SynError, TlsConfig};

#[cfg(feature = "async")]
use std::time::Duration;
#[cfg(feature = "async")]
use synclaire::{handler::ConnectionHandler, AcceptMode, AsyncServer};
#[cfg(feature = "async")]
use tracing_subscriber::EnvFilter;

struct TlsEchoHandler;

#[cfg(feature = "async")]
impl ConnectionHandler for TlsEchoHandler {
    fn handle<'a>(&'a self, mut connection: synclaire::Connection) -> synclaire::handler::HandlerFuture<'a> {
        Box::pin(async move {
            let peer = connection.peer_addr();

            if connection.is_tls() {
                if let Some(tls_stream) = connection.async_stream().expect("async connection").as_server_tls() {
                    let (_, session) = tls_stream.get_ref();
                    let protocol = session.alpn_protocol().map(String::from_utf8_lossy);
                    log::info!("TLS handshake complete peer={} alpn={:?}", peer, protocol);
                }
            } else {
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

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    log::info!("starting TLS echo server on port {}", port);

    let config = ServerConfig::builder()
        .name("tls-echo-server")
        .connection_timeout(Duration::from_secs(60))
        .tls(tls)
        .accept_mode(AcceptMode::Tls)
        .build();

    AsyncServer::from_listener(listener, config, TlsEchoHandler).run().await
}

#[cfg(all(not(feature = "async"), feature = "sync"))]
impl synclaire::SyncConnectionHandler for TlsEchoHandler {
    fn handle(&self, conn: synclaire::Connection) -> synclaire::error::Result<()> {
        use std::io::{Read, Write};
        let peer = conn.peer_addr();
        let is_tls = conn.is_tls();
        if is_tls {
            log::info!("TLS handshake complete peer={}", peer);
        } else {
            log::info!("plain TCP connection on mixed-mode server peer={}", peer);
        }
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

#[cfg(all(not(feature = "async"), feature = "sync"))]
fn main() -> Result<(), SynError> {
    let tls = TlsConfig::builder()
        .enabled(true)
        .server_name("localhost")
        .certificate_chain(PemSource::file("examples/certs/server.crt"))
        .private_key(PemSource::file("examples/certs/server.key"))
        .build();

    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    log::info!("starting TLS echo server on port {}", port);

    let config = ServerConfig::builder()
        .name("tls-echo-server")
        .tls(tls)
        .build();
    synclaire::SyncServer::from_listener(listener, config, TlsEchoHandler).run()
}

#[cfg(not(any(feature = "async", feature = "sync")))]
fn main() {
    eprintln!("enable either the async or sync feature");
}