use std::net::SocketAddr;

use crate::handler::ConnectionMetadata;

pub fn metadata(
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    tls: bool,
) -> ConnectionMetadata {
    ConnectionMetadata::new(peer_addr, local_addr, tls)
}

#[cfg(feature = "async")]
pub async fn set_nodelay_async(
    stream: &tokio::net::TcpStream,
    enabled: bool,
) -> std::io::Result<()> {
    stream.set_nodelay(enabled)
}

#[cfg(feature = "sync")]
pub fn set_nodelay_sync(stream: &std::net::TcpStream, enabled: bool) -> std::io::Result<()> {
    stream.set_nodelay(enabled)
}
