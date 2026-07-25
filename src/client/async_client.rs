use crate::{
    client::{tcp, tls},
    config::ClientConfig,
    handler::Connection,
    SynError,
};

pub struct AsyncClient {
    config: ClientConfig,
}

impl AsyncClient {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    pub async fn connect(self) -> Result<Connection, SynError> {
        log::info!("client connecting to {}", self.config.connect_addr);

        let stream = tcp::connect_async(self.config.connect_addr).await?;
        if let Err(error) = stream.set_nodelay(self.config.tcp_nodelay) {
            log::debug!("failed to set TCP_NODELAY: {}", error);
        }

        let local_addr = stream.local_addr().ok();
        let peer_addr = stream.peer_addr()?;

        if self.config.tls.enabled {
            let tls_stream = tls::connect_async(stream, &self.config.tls).await?;
            let mut metadata = crate::handler::ConnectionMetadata::new(peer_addr, local_addr, true);
            metadata.tls_server_name = self.config.tls.server_name.clone();
            Ok(Connection::from_client_tls(metadata, tls_stream))
        } else {
            let metadata = crate::handler::ConnectionMetadata::new(peer_addr, local_addr, false);
            Ok(Connection::from_async_tcp(metadata, stream))
        }
    }
}