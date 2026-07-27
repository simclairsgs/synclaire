#[cfg(any(feature = "rustls-backend", feature = "aws-lc-backend"))]
use crate::{config::TlsConfig, error::SynError, tls as syn_tls};

#[cfg(all(
    feature = "async",
    any(feature = "rustls-backend", feature = "aws-lc-backend")
))]
pub async fn connect_async(
    stream: tokio::net::TcpStream,
    config: &TlsConfig,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, SynError> {
    let connector = syn_tls::rustls::async_client_connector(config)?;
    let server_name = syn_tls::rustls::server_name(config)?;
    let tls_stream = connector.connect(server_name, stream).await?;
    Ok(tls_stream)
}

#[cfg(all(
    feature = "sync",
    any(feature = "rustls-backend", feature = "aws-lc-backend")
))]
pub fn connect_sync(
    stream: std::net::TcpStream,
    config: &TlsConfig,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>, SynError> {
    let client_config = syn_tls::rustls::build_client_config(config)?;
    let server_name = syn_tls::rustls::server_name(config)?;
    let connection = rustls::ClientConnection::new(client_config, server_name)?;
    let tls_stream = rustls::StreamOwned::new(connection, stream);
    Ok(tls_stream)
}
