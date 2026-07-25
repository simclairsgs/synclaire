use crate::{
    config::ClientConfig,
    handler::Connection,
    SynError,
};
#[cfg(any(feature = "rustls-backend", feature = "aws-lc-backend"))]
use crate::client::tls;

pub struct SyncClient {
    config: ClientConfig,
}

impl SyncClient {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    pub fn connect(self) -> Result<Connection, SynError> {
        log::info!("client connecting to {}", self.config.connect_addr);

        let timeout = self.config.connection_timeout;
        let stream = std::net::TcpStream::connect_timeout(&self.config.connect_addr.into(), timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        if let Err(error) = stream.set_nodelay(self.config.tcp_nodelay) {
            log::debug!("failed to set TCP_NODELAY: {}", error);
        }

        let local_addr = stream.local_addr().ok();
        let peer_addr = stream.peer_addr()?;

        if self.config.tls.enabled {
            #[cfg(any(feature = "rustls-backend", feature = "aws-lc-backend"))]
            {
                let tls_stream = tls::connect_sync(stream, &self.config.tls)?;
                let mut metadata = crate::handler::ConnectionMetadata::new(peer_addr, local_addr, true);
                metadata.tls_server_name = self.config.tls.server_name.clone();
                return Ok(Connection::from_sync_client_tls(metadata, tls_stream));
            }
            #[cfg(not(any(feature = "rustls-backend", feature = "aws-lc-backend")))]
            return Err(SynError::UnsupportedFeature(
                "TLS requires the rustls-backend or aws-lc-backend feature",
            ));
        } else {
            let metadata = crate::handler::ConnectionMetadata::new(peer_addr, local_addr, false);
            Ok(Connection::from_sync_tcp(metadata, stream))
        }
    }
}