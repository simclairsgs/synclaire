use std::{future::Future, net::SocketAddr};

#[cfg(feature = "async")]
use std::{io, pin::Pin, task::{Context, Poll}};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(all(feature = "sync", not(feature = "async")))]
use std::io;

#[cfg(feature = "sync")]
use std::io::{Read, Write};

#[cfg(any(feature = "async", feature = "sync"))]
use futures::future::BoxFuture;

use crate::{guard::GuardSession, SynError};

#[cfg(any(feature = "async", feature = "sync"))]
pub type HandlerResult = Result<(), SynError>;
#[cfg(any(feature = "async", feature = "sync"))]
pub type HandlerFuture<'a> = BoxFuture<'a, HandlerResult>;

#[derive(Clone, Debug)]
pub struct ConnectionMetadata {
    pub peer_addr: SocketAddr,
    pub local_addr: Option<SocketAddr>,
    pub tls: bool,
    pub tls_server_name: Option<String>,
}

impl ConnectionMetadata {
    pub fn new(peer_addr: SocketAddr, local_addr: Option<SocketAddr>, tls: bool) -> Self {
        Self {
            peer_addr,
            local_addr,
            tls,
            tls_server_name: None,
        }
    }
}

/// Concrete async transport. Pattern-match to get the real TCP or TLS socket,
/// or use it directly as `AsyncRead + AsyncWrite`.
#[cfg(feature = "async")]
pub enum AsyncStream {
    /// Plain TCP connection.
    Tcp(tokio::net::TcpStream),
    /// TLS connection accepted on the server side.
    ServerTls(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
    /// TLS connection established on the client side.
    ClientTls(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
}

#[cfg(feature = "async")]
impl AsyncStream {
    /// `true` for any TLS variant.
    pub fn is_tls(&self) -> bool {
        matches!(self, AsyncStream::ServerTls(_) | AsyncStream::ClientTls(_))
    }

    /// Plain TCP socket, `None` if TLS-wrapped.
    pub fn as_tcp(&self) -> Option<&tokio::net::TcpStream> {
        match self { AsyncStream::Tcp(s) => Some(s), _ => None }
    }

    /// Mutable plain TCP socket, `None` if TLS-wrapped.
    pub fn as_tcp_mut(&mut self) -> Option<&mut tokio::net::TcpStream> {
        match self { AsyncStream::Tcp(s) => Some(s), _ => None }
    }

    /// Server-side TLS stream, or `None`.
    pub fn as_server_tls(&self) -> Option<&tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
        match self { AsyncStream::ServerTls(s) => Some(s), _ => None }
    }

    /// Mutable server-side TLS stream, or `None`.
    pub fn as_server_tls_mut(&mut self) -> Option<&mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
        match self { AsyncStream::ServerTls(s) => Some(s), _ => None }
    }

    /// Client-side TLS stream, or `None`.
    pub fn as_client_tls(&self) -> Option<&tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        match self { AsyncStream::ClientTls(s) => Some(s), _ => None }
    }

    /// Mutable client-side TLS stream, or `None`.
    pub fn as_client_tls_mut(&mut self) -> Option<&mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        match self { AsyncStream::ClientTls(s) => Some(s), _ => None }
    }

    /// Underlying TCP socket regardless of TLS wrapping.
    pub fn tcp(&self) -> &tokio::net::TcpStream {
        match self {
            AsyncStream::Tcp(s) => s,
            AsyncStream::ServerTls(s) => s.get_ref().0,
            AsyncStream::ClientTls(s) => s.get_ref().0,
        }
    }
}

#[cfg(feature = "async")]
impl AsyncRead for AsyncStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AsyncStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            AsyncStream::ServerTls(s) => Pin::new(s).poll_read(cx, buf),
            AsyncStream::ClientTls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

#[cfg(feature = "async")]
impl AsyncWrite for AsyncStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            AsyncStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            AsyncStream::ServerTls(s) => Pin::new(s).poll_write(cx, buf),
            AsyncStream::ClientTls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AsyncStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            AsyncStream::ServerTls(s) => Pin::new(s).poll_flush(cx),
            AsyncStream::ClientTls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AsyncStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            AsyncStream::ServerTls(s) => Pin::new(s).poll_shutdown(cx),
            AsyncStream::ClientTls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Concrete sync transport.
#[cfg(feature = "sync")]
pub enum SyncStream {
    /// Plain TCP connection.
    Tcp(std::net::TcpStream),
    /// TLS connection accepted on the server side.
    #[cfg(feature = "rustls-backend")]
    ServerTls(rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>),
    /// TLS connection established on the client side.
    #[cfg(feature = "rustls-backend")]
    ClientTls(rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>),
}

#[cfg(feature = "sync")]
impl SyncStream {
    pub fn is_tls(&self) -> bool {
        #[cfg(feature = "rustls-backend")]
        { matches!(self, SyncStream::ServerTls(_) | SyncStream::ClientTls(_)) }
        #[cfg(not(feature = "rustls-backend"))]
        { false }
    }
}

#[cfg(feature = "sync")]
impl Read for SyncStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            SyncStream::Tcp(s) => s.read(buf),
            #[cfg(feature = "rustls-backend")]
            SyncStream::ServerTls(s) => s.read(buf),
            #[cfg(feature = "rustls-backend")]
            SyncStream::ClientTls(s) => s.read(buf),
        }
    }
}

#[cfg(feature = "sync")]
impl Write for SyncStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            SyncStream::Tcp(s) => s.write(buf),
            #[cfg(feature = "rustls-backend")]
            SyncStream::ServerTls(s) => s.write(buf),
            #[cfg(feature = "rustls-backend")]
            SyncStream::ClientTls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            SyncStream::Tcp(s) => s.flush(),
            #[cfg(feature = "rustls-backend")]
            SyncStream::ServerTls(s) => s.flush(),
            #[cfg(feature = "rustls-backend")]
            SyncStream::ClientTls(s) => s.flush(),
        }
    }
}

/// Unified stream wrapper — either async or sync.
pub enum ConnectionStream {
    #[cfg(feature = "async")]
    Async(AsyncStream),
    #[cfg(feature = "sync")]
    Sync(SyncStream),
}

impl ConnectionStream {
    pub fn is_tls(&self) -> bool {
        // Deref so that the match is on `ConnectionStream` (not `&ConnectionStream`).
        // When neither feature is enabled the enum is uninhabited, and matching on
        // an uninhabited value with no arms is valid Rust — the block is unreachable.
        match *self {
            #[cfg(feature = "async")]
            ConnectionStream::Async(ref s) => s.is_tls(),
            #[cfg(feature = "sync")]
            ConnectionStream::Sync(ref s) => s.is_tls(),
        }
    }

    #[cfg(feature = "async")]
    pub fn as_async(&self) -> Option<&AsyncStream> {
        match self {
            ConnectionStream::Async(s) => Some(s),
            #[cfg(feature = "sync")]
            ConnectionStream::Sync(_) => None,
        }
    }

    #[cfg(feature = "async")]
    pub fn as_async_mut(&mut self) -> Option<&mut AsyncStream> {
        match self {
            ConnectionStream::Async(s) => Some(s),
            #[cfg(feature = "sync")]
            ConnectionStream::Sync(_) => None,
        }
    }

    #[cfg(feature = "async")]
    pub fn into_async(self) -> Option<AsyncStream> {
        match self {
            ConnectionStream::Async(s) => Some(s),
            #[cfg(feature = "sync")]
            ConnectionStream::Sync(_) => None,
        }
    }

    #[cfg(feature = "sync")]
    pub fn as_sync(&self) -> Option<&SyncStream> {
        match self {
            ConnectionStream::Sync(s) => Some(s),
            #[cfg(feature = "async")]
            ConnectionStream::Async(_) => None,
        }
    }

    #[cfg(feature = "sync")]
    pub fn as_sync_mut(&mut self) -> Option<&mut SyncStream> {
        match self {
            ConnectionStream::Sync(s) => Some(s),
            #[cfg(feature = "async")]
            ConnectionStream::Async(_) => None,
        }
    }

    #[cfg(feature = "sync")]
    pub fn into_sync(self) -> Option<SyncStream> {
        match self {
            ConnectionStream::Sync(s) => Some(s),
            #[cfg(feature = "async")]
            ConnectionStream::Async(_) => None,
        }
    }
}

pub struct Connection {
    metadata: ConnectionMetadata,
    stream: Option<ConnectionStream>,
    guard_session: Option<GuardSession>,
}

impl Connection {
    /// Build from a plain async TCP stream.
    #[cfg(feature = "async")]
    pub fn from_async_tcp(metadata: ConnectionMetadata, stream: tokio::net::TcpStream) -> Self {
        Self { metadata, stream: Some(ConnectionStream::Async(AsyncStream::Tcp(stream))), guard_session: None }
    }

    /// Build from a server-side async TLS stream.
    #[cfg(feature = "async")]
    pub fn from_async_server_tls(
        metadata: ConnectionMetadata,
        stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ) -> Self {
        Self { metadata, stream: Some(ConnectionStream::Async(AsyncStream::ServerTls(stream))), guard_session: None }
    }

    /// Build from a client-side async TLS stream.
    #[cfg(feature = "async")]
    pub fn from_client_tls(
        metadata: ConnectionMetadata,
        stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    ) -> Self {
        Self { metadata, stream: Some(ConnectionStream::Async(AsyncStream::ClientTls(stream))), guard_session: None }
    }

    /// Build from an already-resolved async stream enum.
    #[cfg(feature = "async")]
    pub fn from_async_stream(metadata: ConnectionMetadata, stream: AsyncStream) -> Self {
        Self { metadata, stream: Some(ConnectionStream::Async(stream)), guard_session: None }
    }

    /// Build from a plain sync TCP stream.
    #[cfg(feature = "sync")]
    pub fn from_sync_tcp(metadata: ConnectionMetadata, stream: std::net::TcpStream) -> Self {
        Self { metadata, stream: Some(ConnectionStream::Sync(SyncStream::Tcp(stream))), guard_session: None }
    }

    /// Build from a sync server-side TLS stream.
    #[cfg(all(feature = "sync", feature = "rustls-backend"))]
    pub(crate) fn from_sync_server_tls(
        metadata: ConnectionMetadata,
        stream: rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>,
    ) -> Self {
        Self { metadata, stream: Some(ConnectionStream::Sync(SyncStream::ServerTls(stream))), guard_session: None }
    }

    /// Build from a sync client-side TLS stream.
    #[cfg(all(feature = "sync", feature = "rustls-backend"))]
    pub(crate) fn from_sync_client_tls(
        metadata: ConnectionMetadata,
        stream: rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
    ) -> Self {
        Self { metadata, stream: Some(ConnectionStream::Sync(SyncStream::ClientTls(stream))), guard_session: None }
    }

    pub(crate) fn with_guard_session(mut self, guard_session: GuardSession) -> Self {
        self.guard_session = Some(guard_session);
        self
    }

    /// Per-connection metadata.
    pub fn metadata(&self) -> &ConnectionMetadata {
        &self.metadata
    }

    /// Reference to the raw stream.
    pub fn stream(&self) -> &ConnectionStream {
        self.stream.as_ref().expect("stream was already taken")
    }

    /// Mutable reference to the raw stream.
    pub fn stream_mut(&mut self) -> &mut ConnectionStream {
        self.stream.as_mut().expect("stream was already taken")
    }

    /// Take ownership of the raw stream — useful for zero-copy proxying.
    pub fn into_stream(mut self) -> ConnectionStream {
        self.stream.take().expect("stream was already taken")
    }

    /// Returns the async stream, or `None` if this is a sync connection.
    #[cfg(feature = "async")]
    pub fn async_stream(&self) -> Option<&AsyncStream> {
        self.stream().as_async()
    }

    /// Returns the mutable async stream, or `None` if this is a sync connection.
    #[cfg(feature = "async")]
    pub fn async_stream_mut(&mut self) -> Option<&mut AsyncStream> {
        self.stream_mut().as_async_mut()
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.metadata.peer_addr
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.metadata.local_addr
    }

    /// `true` if the underlying stream is TLS.
    pub fn is_tls(&self) -> bool {
        self.stream.as_ref().map(|s| s.is_tls()).unwrap_or(false)
    }

    pub fn tls_server_name(&self) -> Option<&str> {
        self.metadata.tls_server_name.as_deref()
    }

    // --- Convenience async I/O helpers ---

    #[cfg(feature = "async")]
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, SynError> {
        let stream = self.stream.as_mut().expect("stream taken").as_async_mut().expect("async stream");
        let read = tokio::io::AsyncReadExt::read(stream, buf).await?;
        if read > 0 {
            if let Some(session) = &self.guard_session {
                session.record_payload(&buf[..read])?;
            }
        }
        Ok(read)
    }

    #[cfg(feature = "async")]
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), SynError> {
        {
            let stream = self.stream.as_mut().expect("stream taken").as_async_mut().expect("async stream");
            tokio::io::AsyncReadExt::read_exact(stream, buf).await?;
        }
        if let Some(session) = &self.guard_session {
            session.record_payload(buf)?;
        }
        Ok(())
    }

    #[cfg(feature = "async")]
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), SynError> {
        {
            let stream = self.stream.as_mut().expect("stream taken").as_async_mut().expect("async stream");
            tokio::io::AsyncWriteExt::write_all(stream, buf).await?;
        }
        if let Some(session) = &self.guard_session {
            session.touch()?;
        }
        Ok(())
    }

    #[cfg(feature = "async")]
    pub async fn flush(&mut self) -> Result<(), SynError> {
        let stream = self.stream.as_mut().expect("stream taken").as_async_mut().expect("async stream");
        tokio::io::AsyncWriteExt::flush(stream).await?;
        Ok(())
    }

    #[cfg(feature = "async")]
    pub async fn shutdown(&mut self) -> Result<(), SynError> {
        let stream = self.stream.as_mut().expect("stream taken").as_async_mut().expect("async stream");
        tokio::io::AsyncWriteExt::shutdown(stream).await?;
        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(session) = &self.guard_session {
            session.close();
        }
    }
}

#[cfg(any(feature = "async", feature = "sync"))]
pub trait ConnectionHandler: Send + Sync + 'static {
    fn handle<'a>(&'a self, connection: Connection) -> HandlerFuture<'a>;
}

#[cfg(any(feature = "async", feature = "sync"))]
impl<F, Fut> ConnectionHandler for F
where
    F: Fn(Connection) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = HandlerResult> + Send + 'static,
{
    fn handle<'a>(&'a self, connection: Connection) -> HandlerFuture<'a> {
        Box::pin((self)(connection))
    }
}

pub(crate) fn attach_guard_session(connection: Connection, guard_session: GuardSession) -> Connection {
    connection.with_guard_session(guard_session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn async_tcp_stream_is_accessible_and_movable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let _client = tokio::net::TcpStream::connect(addr).await.expect("client connect");
        let (server_stream, peer_addr) = listener.accept().await.expect("accept");
        let metadata = ConnectionMetadata::new(peer_addr, None, false);
        let connection = Connection::from_async_tcp(metadata, server_stream);
        assert!(!connection.is_tls());
        assert!(connection.async_stream().expect("async stream").as_tcp().is_some());
        assert!(connection.async_stream().expect("async stream").as_server_tls().is_none());
        match connection.into_stream().into_async().expect("async stream") {
            AsyncStream::Tcp(_) => {}
            _ => panic!("expected TCP stream"),
        }
    }

    #[cfg(feature = "sync")]
    #[test]
    fn sync_tcp_stream_is_accessible_and_movable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let _client = std::thread::spawn(move || std::net::TcpStream::connect(addr));
        let (server_stream, peer_addr) = listener.accept().expect("accept");
        let metadata = ConnectionMetadata::new(peer_addr, None, false);
        let connection = Connection::from_sync_tcp(metadata, server_stream);
        assert!(!connection.is_tls());
        match connection.into_stream().into_sync().expect("sync stream") {
            SyncStream::Tcp(_) => {}
            #[cfg(feature = "rustls-backend")]
            _ => panic!("expected TCP stream"),
        }
    }
}
