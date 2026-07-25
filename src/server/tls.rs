#[cfg(any(feature = "rustls-backend", feature = "aws-lc-backend"))]
use crate::{config::TlsConfig, error::SynError, tls as syn_tls};

#[cfg(all(feature = "async", any(feature = "rustls-backend", feature = "aws-lc-backend")))]
pub async fn accept_async(
    stream: tokio::net::TcpStream,
    config: &TlsConfig,
) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, SynError> {
    let acceptor = syn_tls::rustls::async_server_acceptor(config)?;
    let tls_stream = acceptor.accept(stream).await?;
    Ok(tls_stream)
}

#[cfg(all(feature = "sync", any(feature = "rustls-backend", feature = "aws-lc-backend")))]
pub fn accept_sync(
    stream: std::net::TcpStream,
    config: &TlsConfig,
) -> Result<rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>, SynError> {
    let server_config = syn_tls::rustls::build_server_config(config)?;
    let connection = rustls::ServerConnection::new(server_config)?;
    let tls_stream = rustls::StreamOwned::new(connection, stream);
    Ok(tls_stream)
}
