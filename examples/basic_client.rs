use std::env;
use synclaire::{client::AsyncClient, AsyncStream, ClientConfig, SynError};
use tracing_subscriber::EnvFilter;

#[cfg(feature = "async")]
#[tokio::main]
async fn main() -> Result<(), SynError> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("synclaire=info".parse().unwrap()))
        .try_init()
        .ok();

    let port = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(7000);

    let config = ClientConfig::builder()
        .name("basic-client")
        .connect_addr(format!("127.0.0.1:{}", port).parse().unwrap())
        .build();
    let mut connection = AsyncClient::new(config).connect().await?;

    // Check what you actually got.
    log::info!("connected tls={} peer={}", connection.is_tls(), connection.peer_addr());

    // Pattern-match to reach the concrete socket.
    match connection.async_stream().expect("async connection") {
        AsyncStream::Tcp(tcp) => log::info!("plain TCP socket local={:?}", tcp.local_addr().ok()),
        AsyncStream::ClientTls(tls_stream) => {
            let (_, session) = tls_stream.get_ref();
            log::info!("TLS session alpn={:?}", session.alpn_protocol());
        }
        AsyncStream::ServerTls(_) => unreachable!("client never gets a server-side stream"),
    }

    connection.write_all(b"hello from synclaire\n").await?;
    connection.shutdown().await?;
    log::info!("message sent");
    Ok(())
}

#[cfg(all(not(feature = "async"), feature = "sync"))]
fn main() -> Result<(), SynError> {
    let port = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(7000);

    let config = ClientConfig::builder()
        .name("basic-client")
        .connect_addr(format!("127.0.0.1:{}", port).parse().unwrap())
        .build();
    let mut connection = synclaire::client::SyncClient::new(config).connect()?;
    futures::executor::block_on(async {
        connection.write_all(b"hello from synclaire\n").await?;
        connection.shutdown().await?;
        Ok::<(), SynError>(())
    })?;
    Ok(())
}

#[cfg(not(any(feature = "async", feature = "sync")))]
fn main() {
    eprintln!("enable either the async or sync feature");
}