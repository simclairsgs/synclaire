use std::net::SocketAddr;

use crate::handler::ConnectionMetadata;

pub fn metadata(peer_addr: SocketAddr, local_addr: Option<SocketAddr>, tls: bool) -> ConnectionMetadata {
    ConnectionMetadata::new(peer_addr, local_addr, tls)
}

#[cfg(feature = "async")]
pub async fn connect_async(addr: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    tokio::net::TcpStream::connect(addr).await
}

#[cfg(feature = "sync")]
pub fn connect_sync(addr: SocketAddr) -> std::io::Result<std::net::TcpStream> {
    std::net::TcpStream::connect(addr)
}