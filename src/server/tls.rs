use crate::{config::TlsConfig, error::SynError, tls as syn_tls};

#[cfg(feature = "async")]
pub async fn accept_async(
    stream: tokio::net::TcpStream,
    config: &TlsConfig,
) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, SynError> {
    let acceptor = syn_tls::rustls::async_server_acceptor(config)?;
    let tls_stream = acceptor.accept(stream).await?;
    Ok(tls_stream)
}

#[cfg(feature = "sync")]
pub fn accept_sync(
    stream: std::net::TcpStream,
    config: &TlsConfig,
) -> Result<rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>, SynError> {
    let server_config = syn_tls::rustls::build_server_config(config)?;
    let connection = rustls::ServerConnection::new(server_config)?;
    let tls_stream = rustls::StreamOwned::new(connection, stream);
    Ok(tls_stream)
}

pub fn backend_label(config: &TlsConfig) -> &'static str {
    if config.prefer_aws_lc {
        syn_tls::aws_lc::backend_name()
    } else {
        syn_tls::rustls::backend_name()
    }
}