// TCP proxy module for forwarding connections.
//
// Provides:
// - TcpProxy: per-connection forwarding engine
// - ProxyServer: sync proxy listener with guard stack, routing, and metrics
// - AsyncProxyServer: async variant with TLS offload, routing, and metrics
// - ProxyClient: sync client helper that sends proxy auth preface
// - ProxyAuthHandle: runtime-updatable credentials

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, RwLock};

use crate::metrics::MetricsCollector;
use crate::load_balancer::BackendPool;
use crate::routing::{RouteAction, RoutingTable};

use crate::config::{GuardStackConfig, TlsConfig};
use crate::guard::GuardContext;
use crate::server::build_guard_stack;
use crate::SynError;

/// Authentication configuration for the proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyAuth {
    /// No authentication required.
    None,
    /// Basic HTTP authentication (username:password).
    Basic(String, String),
}

impl ProxyAuth {
    /// Create basic auth with username and password.
    pub fn basic(username: &str, password: &str) -> Self {
        Self::Basic(username.to_string(), password.to_string())
    }

    /// Validate authentication credentials.
    pub fn validate(&self, username: &str, password: &str) -> bool {
        match self {
            ProxyAuth::None => true,
            ProxyAuth::Basic(user, pass) => username == user && password == pass,
        }
    }

    /// Encode credentials for basic auth header.
    pub fn encode_header(&self) -> Option<String> {
        match self {
            ProxyAuth::None => None,
            ProxyAuth::Basic(user, pass) => {
                let credentials = format!("{}:{}", user, pass);
                let encoded = base64::encode(&credentials);
                Some(format!("Basic {}", encoded))
            }
        }
    }

    /// Parse and validate HTTP Authorization header.
    pub fn validate_header(&self, header: &str) -> bool {
        if let ProxyAuth::Basic(expected_user, expected_pass) = self {
            if let Some(payload) = header.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::decode(payload) {
                    if let Ok(credentials) = String::from_utf8(decoded) {
                        if let Some((user, pass)) = credentials.split_once(':') {
                            return user == expected_user && pass == expected_pass;
                        }
                    }
                }
            }
        }
        false
    }
}

/// Shared, runtime-updatable authentication handle.
#[derive(Clone, Debug)]
pub struct ProxyAuthHandle {
    inner: Arc<RwLock<ProxyAuth>>,
}

impl ProxyAuthHandle {
    /// Create a new shared auth handle.
    pub fn new(initial: ProxyAuth) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial)),
        }
    }

    /// Snapshot the current authentication state.
    pub fn current(&self) -> Result<ProxyAuth, SynError> {
        self.inner
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| SynError::runtime("proxy auth lock poisoned"))
    }

    /// Replace the current auth strategy.
    pub fn set(&self, auth: ProxyAuth) -> Result<(), SynError> {
        self.inner
            .write()
            .map(|mut guard| {
                *guard = auth;
            })
            .map_err(|_| SynError::runtime("proxy auth lock poisoned"))
    }

    /// Switch to no-auth mode.
    pub fn set_none(&self) -> Result<(), SynError> {
        self.set(ProxyAuth::None)
    }

    /// Switch to basic-auth mode.
    pub fn set_basic(&self, username: &str, password: &str) -> Result<(), SynError> {
        self.set(ProxyAuth::basic(username, password))
    }
}

/// TCP proxy configuration.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// Address to listen on.
    pub listen_addr: SocketAddr,
    /// Default backend server address to forward to (used when no pool or routing table is set).
    pub backend_addr: SocketAddr,
    /// Authentication configuration.
    pub auth: ProxyAuth,
    /// Buffer size for forwarding (default 8KB).
    pub buffer_size: usize,
    /// Optional guard stack configuration for the proxy server.
    pub guards: GuardStackConfig,
    /// Optional TLS offload server settings.
    pub tls_offload: Option<TlsConfig>,
    /// Optional routing table (overrides backend_addr when set; Pool actions beat backend_pool).
    pub routing: Option<Arc<RoutingTable>>,
    /// Optional load-balancer pool for direct (non-routed) connections.
    pub backend_pool: Option<Arc<BackendPool>>,
}

impl ProxyConfig {
    /// Create a new proxy configuration.
    pub fn new(listen_addr: SocketAddr, backend_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            backend_addr,
            auth: ProxyAuth::None,
            buffer_size: 8192,
            guards: GuardStackConfig::default(),
            tls_offload: None,
            routing: None,
            backend_pool: None,
        }
    }

    /// Set authentication for the proxy.
    pub fn with_auth(mut self, auth: ProxyAuth) -> Self {
        self.auth = auth;
        self
    }

    /// Set buffer size for forwarding.
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Attach guard configuration for ProxyServer.
    pub fn with_guards(mut self, guards: GuardStackConfig) -> Self {
        self.guards = guards;
        self
    }

    /// Enable TLS offload configuration for incoming proxy connections.
    ///
    /// Note: Sync ProxyServer currently validates this option and returns
    /// `UnsupportedFeature` when enabled. The field exists so apps can share
    /// config between sync and future async offload runtimes.
    pub fn with_tls_offload(mut self, tls: TlsConfig) -> Self {
        self.tls_offload = Some(tls);
        self
    }

    /// Attach a routing table that overrides `backend_addr` per-connection.
    pub fn with_routing(mut self, routing: Arc<RoutingTable>) -> Self {
        self.routing = Some(routing);
        self
    }

    /// Attach a load-balancer backend pool for direct (non-routed) connections.
    /// Ignored when a routing table is also set and the matched rule is `Forward` or `Pool`.
    pub fn with_backend_pool(mut self, pool: Arc<BackendPool>) -> Self {
        self.backend_pool = Some(pool);
        self
    }
}

/// Parse HTTP proxy auth headers from a raw byte slice, return trailing payload.
fn parse_http_auth_from_bytes(data: &[u8], auth: &ProxyAuth) -> Result<Vec<u8>, SynError> {
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(data.len());

    let headers_raw = &data[..header_end];
    let trailing = data[header_end..].to_vec();
    let headers = String::from_utf8_lossy(headers_raw);

    for line in headers.lines().skip(1) {
        if let Some(value) = line.strip_prefix("Authorization: ") {
            if auth.validate_header(value.trim()) {
                return Ok(trailing);
            }
            return Err(SynError::authentication_error("Invalid credentials"));
        }
    }

    Err(SynError::authentication_error("Authorization required"))
}

/// TCP proxy connection handler.
#[derive(Clone, Debug)]
pub struct TcpProxy {
    config: ProxyConfig,
    auth_handle: Option<ProxyAuthHandle>,
}

impl TcpProxy {
    /// Create a new TCP proxy forwarding engine.
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            auth_handle: None,
        }
    }

    /// Attach a dynamic auth handle for runtime credential updates.
    pub fn with_auth_handle(mut self, auth_handle: ProxyAuthHandle) -> Self {
        self.auth_handle = Some(auth_handle);
        self
    }

    fn effective_auth(&self) -> Result<ProxyAuth, SynError> {
        match &self.auth_handle {
            Some(handle) => handle.current(),
            None => Ok(self.config.auth.clone()),
        }
    }

    /// Forward a client connection to the backend server.
    pub fn forward(&self, client: TcpStream) -> Result<(), SynError> {
        self.forward_to(client, None)
    }

    /// Forward with an explicit backend address (used by ProxyServer routing).
    pub fn forward_to(&self, mut client: TcpStream, override_backend: Option<SocketAddr>) -> Result<(), SynError> {
        let effective_auth = self.effective_auth()?;

        // Validate auth and capture any payload bytes that arrived after the
        // \r\n\r\n header terminator. These would be silently lost if we used
        // a BufReader, because BufReader buffers ahead and those bytes never
        // reach the original TcpStream.
        let trailing_payload = if matches!(effective_auth, ProxyAuth::Basic(_, _)) {
            self.validate_http_auth_stream(&mut client, &effective_auth)?
        } else {
            Vec::new()
        };

        let backend_addr = override_backend.unwrap_or(self.config.backend_addr);
        let mut backend = TcpStream::connect(backend_addr)
            .map_err(|e| SynError::connection_error(e.to_string()))?;

        // Write any payload the client sent immediately after the CONNECT
        // headers before handing off to bidirectional forwarding.
        if !trailing_payload.is_empty() {
            backend.write_all(&trailing_payload).map_err(|e| {
                SynError::connection_error(format!("Failed to write trailing payload to backend: {}", e))
            })?;
        }

        self.forward_bidirectional(&client, &backend)
    }

    /// Read HTTP proxy auth headers directly from the stream without BufReader,
    /// returning any bytes that arrived after the \r\n\r\n terminator so they
    /// are not silently dropped before backend forwarding begins.
    fn validate_http_auth_stream(&self, client: &mut TcpStream, auth: &ProxyAuth) -> Result<Vec<u8>, SynError> {
        let mut data = Vec::with_capacity(1024);
        let mut chunk = [0u8; 512];

        loop {
            let n = client.read(&mut chunk).map_err(|e| {
                SynError::connection_error(format!("Failed to read auth headers: {}", e))
            })?;

            if n == 0 {
                return Err(SynError::authentication_error("connection closed before authorization headers"));
            }

            data.extend_from_slice(&chunk[..n]);

            if data.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }

            if data.len() > 64 * 1024 {
                return Err(SynError::authentication_error("proxy auth headers too large"));
            }
        }

        parse_http_auth_from_bytes(&data, auth)
    }

    /// Forward data bidirectionally between client and backend.
    fn forward_bidirectional(&self, client: &TcpStream, backend: &TcpStream) -> Result<(), SynError> {
        use std::thread;

        let mut client_clone = client.try_clone().map_err(|e| {
            SynError::connection_error(format!("Failed to clone client: {}", e))
        })?;

        let mut backend_clone = backend.try_clone().map_err(|e| {
            SynError::connection_error(format!("Failed to clone backend: {}", e))
        })?;

        let mut client_for_reverse = client.try_clone().map_err(|e| {
            SynError::connection_error(format!("Failed to clone client for reverse: {}", e))
        })?;

        let mut backend_for_reverse = backend.try_clone().map_err(|e| {
            SynError::connection_error(format!("Failed to clone backend for reverse: {}", e))
        })?;

        let buffer_size = self.config.buffer_size;

        let client_to_backend = thread::spawn(move || {
            let mut buf = vec![0u8; buffer_size];
            loop {
                match client_clone.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if backend_clone.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let backend_to_client = thread::spawn(move || {
            let mut buf = vec![0u8; buffer_size];
            loop {
                match backend_for_reverse.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if client_for_reverse.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let _ = client_to_backend.join();
        let _ = backend_to_client.join();
        Ok(())
    }
}

/// Sync proxy server runner.
pub struct ProxyServer {
    config: ProxyConfig,
    auth_handle: Option<ProxyAuthHandle>,
    metrics: Option<Arc<MetricsCollector>>,
}

impl ProxyServer {
    /// Create a new proxy server.
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            auth_handle: None,
            metrics: None,
        }
    }

    /// Attach dynamic auth handle for runtime credential updates.
    pub fn with_auth_handle(mut self, auth_handle: ProxyAuthHandle) -> Self {
        self.auth_handle = Some(auth_handle);
        self
    }

    /// Attach a metrics collector.
    pub fn with_metrics(mut self, metrics: Arc<MetricsCollector>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Get a clone of the auth handle when configured.
    pub fn auth_handle(&self) -> Option<ProxyAuthHandle> {
        self.auth_handle.clone()
    }

    /// Run the proxy server loop.
    pub fn run(&self) -> Result<(), SynError> {
        if self.config.tls_offload.as_ref().is_some_and(|tls| tls.enabled) {
            return Err(SynError::UnsupportedFeature(
                "sync proxy TLS offload is not implemented yet",
            ));
        }

        let listener = TcpListener::bind(self.config.listen_addr)?;
        let guards = build_guard_stack(&self.config.guards);

        log::info!(
            "proxy server listening on {} forwarding to {}",
            self.config.listen_addr,
            self.config.backend_addr
        );

        for incoming in listener.incoming() {
            let stream = match incoming {
                Ok(stream) => stream,
                Err(error) => {
                    log::warn!("proxy accept error: {}", error);
                    continue;
                }
            };

            let peer_addr = match stream.peer_addr() {
                Ok(addr) => addr,
                Err(error) => {
                    log::warn!("proxy peer address error: {}", error);
                    continue;
                }
            };

            // Resolve routing before guard check so Reject rules skip guard overhead.
            let backend_override = if let Some(table) = &self.config.routing {
                match table.resolve(peer_addr) {
                    RouteAction::Forward(addr) => Some(addr),
                    RouteAction::Pool(pool) => match pool.select(peer_addr) {
                        Some(addr) => Some(addr),
                        None => {
                            log::warn!("[{}] routing pool is empty", peer_addr);
                            continue;
                        }
                    },
                    RouteAction::Reject => {
                        log::warn!("[{}] routing table rejected connection", peer_addr);
                        if let Some(m) = &self.metrics {
                            m.record_failure(Some("proxy"), peer_addr.ip());
                        }
                        continue;
                    }
                }
            } else if let Some(pool) = &self.config.backend_pool {
                match pool.select(peer_addr) {
                    Some(addr) => Some(addr),
                    None => {
                        log::warn!("[{}] backend pool is empty", peer_addr);
                        continue;
                    }
                }
            } else {
                None
            };

            let local_addr = stream.local_addr().ok();
            let context = GuardContext::new(peer_addr, local_addr, false);

            let guard_session = match guards.reserve(context.clone()) {
                Ok(session) => session,
                Err(error) => {
                    log::warn!("[{}] proxy guard rejected connection: {}", peer_addr, error);
                    if let Some(m) = &self.metrics {
                        m.record_failure(Some("proxy"), peer_addr.ip());
                    }
                    continue;
                }
            };

            if let Err(error) = guard_session.mark_established() {
                log::warn!("[{}] proxy guard establish reject: {}", peer_addr, error);
                if let Some(m) = &self.metrics {
                    m.record_failure(Some("proxy"), peer_addr.ip());
                }
                guard_session.close();
                continue;
            }

            if let Some(m) = &self.metrics {
                m.record_tcp_connection(Some("proxy"), peer_addr.ip());
            }

            let mut proxy = TcpProxy::new(self.config.clone());
            if let Some(handle) = &self.auth_handle {
                proxy = proxy.with_auth_handle(handle.clone());
            }

            let metrics = self.metrics.clone();

            std::thread::spawn(move || {
                if let Err(error) = proxy.forward_to(stream, backend_override) {
                    log::warn!("[{}] proxy forwarding error: {}", peer_addr, error);
                }
                if let Some(m) = metrics {
                    m.record_connection_close(Some("proxy"), peer_addr.ip());
                }
                guard_session.close();
            });
        }

        Ok(())
    }
}

/// Async proxy server runner with optional TLS offload.
#[cfg(feature = "async")]
pub struct AsyncProxyServer {
    config: ProxyConfig,
    auth_handle: Option<ProxyAuthHandle>,
    metrics: Option<Arc<MetricsCollector>>,
}

#[cfg(feature = "async")]
impl AsyncProxyServer {
    /// Create a new async proxy server.
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            auth_handle: None,
            metrics: None,
        }
    }

    /// Attach dynamic auth handle for runtime credential updates.
    pub fn with_auth_handle(mut self, auth_handle: ProxyAuthHandle) -> Self {
        self.auth_handle = Some(auth_handle);
        self
    }

    /// Attach a metrics collector.
    pub fn with_metrics(mut self, metrics: Arc<MetricsCollector>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Run the async proxy loop.
    pub async fn run(&self) -> Result<(), SynError> {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(self.config.listen_addr).await?;
        let guards = build_guard_stack(&self.config.guards);

        log::info!(
            "async proxy server listening on {} forwarding to {}",
            self.config.listen_addr,
            self.config.backend_addr
        );

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let local_addr = stream.local_addr().ok();
            let tls_enabled = self.config.tls_offload.as_ref().is_some_and(|tls| tls.enabled);
            let context = GuardContext::new(peer_addr, local_addr, tls_enabled);

            // Routing table resolves which backend to forward to.
            let backend_override = if let Some(table) = &self.config.routing {
                match table.resolve(peer_addr) {
                    RouteAction::Forward(addr) => Some(addr),
                    RouteAction::Pool(pool) => match pool.select(peer_addr) {
                        Some(addr) => Some(addr),
                        None => {
                            log::warn!("[{}] async routing pool is empty", peer_addr);
                            continue;
                        }
                    },
                    RouteAction::Reject => {
                        log::warn!("[{}] async routing table rejected connection", peer_addr);
                        if let Some(m) = &self.metrics {
                            m.record_failure(Some("async-proxy"), peer_addr.ip());
                        }
                        continue;
                    }
                }
            } else if let Some(pool) = &self.config.backend_pool {
                match pool.select(peer_addr) {
                    Some(addr) => Some(addr),
                    None => {
                        log::warn!("[{}] async backend pool is empty", peer_addr);
                        continue;
                    }
                }
            } else {
                None
            };

            let guard_session = match guards.reserve(context.clone()) {
                Ok(session) => session,
                Err(error) => {
                    log::warn!("[{}] async proxy guard rejected connection: {}", peer_addr, error);
                    if let Some(m) = &self.metrics {
                        m.record_failure(Some("async-proxy"), peer_addr.ip());
                    }
                    continue;
                }
            };

            if let Err(error) = guard_session.mark_established() {
                log::warn!("[{}] async proxy guard establish reject: {}", peer_addr, error);
                if let Some(m) = &self.metrics {
                    m.record_failure(Some("async-proxy"), peer_addr.ip());
                }
                guard_session.close();
                continue;
            }

            if let Some(m) = &self.metrics {
                m.record_tcp_connection(Some("async-proxy"), peer_addr.ip());
            }

            let config = self.config.clone();
            let auth_handle = self.auth_handle.clone();
            let metrics = self.metrics.clone();

            tokio::spawn(async move {
                if let Err(error) = forward_async_connection(stream, config, auth_handle, backend_override).await {
                    log::warn!("[{}] async proxy forwarding error: {}", peer_addr, error);
                }
                if let Some(m) = metrics {
                    m.record_connection_close(Some("async-proxy"), peer_addr.ip());
                }
                guard_session.close();
            });
        }
    }
}

#[cfg(feature = "async")]
fn resolve_auth(config_auth: &ProxyAuth, auth_handle: &Option<ProxyAuthHandle>) -> Result<ProxyAuth, SynError> {
    match auth_handle {
        Some(handle) => handle.current(),
        None => Ok(config_auth.clone()),
    }
}

#[cfg(feature = "async")]
async fn forward_async_connection(
    stream: tokio::net::TcpStream,
    config: ProxyConfig,
    auth_handle: Option<ProxyAuthHandle>,
    backend_override: Option<SocketAddr>,
) -> Result<(), SynError> {
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    async fn authenticate_stream<S>(stream: &mut S, auth: &ProxyAuth) -> Result<Vec<u8>, SynError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if !matches!(auth, ProxyAuth::Basic(_, _)) {
            return Ok(Vec::new());
        }

        let mut data = Vec::with_capacity(1024);
        let mut chunk = [0u8; 512];

        let header_end = loop {
            let read = stream
                .read(&mut chunk)
                .await
                .map_err(|e| SynError::connection_error(e.to_string()))?;

            if read == 0 {
                return Err(SynError::authentication_error(
                    "connection closed before authorization headers",
                ));
            }

            data.extend_from_slice(&chunk[..read]);
            if let Some(index) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                break index + 4;
            }

            if data.len() > 64 * 1024 {
                return Err(SynError::authentication_error("proxy auth headers too large"));
            }
        };

        let headers_raw = &data[..header_end];
        let trailing_payload = data[header_end..].to_vec();
        let headers = String::from_utf8_lossy(headers_raw);

        for line in headers.lines() {
            if let Some(value) = line.strip_prefix("Authorization: ") {
                if auth.validate_header(value.trim()) {
                    return Ok(trailing_payload);
                }
                return Err(SynError::authentication_error("Invalid credentials"));
            }
        }

        Err(SynError::authentication_error("Authorization required"))
    }

    let auth = resolve_auth(&config.auth, &auth_handle)?;
    let backend_addr = backend_override.unwrap_or(config.backend_addr);
    let mut backend = tokio::net::TcpStream::connect(backend_addr)
        .await
        .map_err(|e| SynError::connection_error(e.to_string()))?;

    if let Some(tls) = &config.tls_offload {
        if tls.enabled {
            #[cfg(feature = "rustls-backend")]
            {
                let acceptor = crate::tls::async_server_acceptor(tls)?;
                let mut client = acceptor
                    .accept(stream)
                    .await
                    .map_err(|e| SynError::tls(e.to_string()))?;

                let preloaded_payload = authenticate_stream(&mut client, &auth).await?;
                if !preloaded_payload.is_empty() {
                    backend
                        .write_all(&preloaded_payload)
                        .await
                        .map_err(|e| SynError::connection_error(e.to_string()))?;
                }

                tokio::io::copy_bidirectional(&mut client, &mut backend)
                    .await
                    .map_err(|e| SynError::connection_error(e.to_string()))?;
                return Ok(());
            }

            #[cfg(not(feature = "rustls-backend"))]
            {
                let _ = stream;
                return Err(SynError::UnsupportedFeature(
                    "proxy TLS offload requires rustls-backend feature",
                ));
            }
        }
    }

    let mut client = stream;
    let preloaded_payload = authenticate_stream(&mut client, &auth).await?;
    if !preloaded_payload.is_empty() {
        backend
            .write_all(&preloaded_payload)
            .await
            .map_err(|e| SynError::connection_error(e.to_string()))?;
    }

    tokio::io::copy_bidirectional(&mut client, &mut backend)
        .await
        .map_err(|e| SynError::connection_error(e.to_string()))?;
    Ok(())
}

/// Sync proxy client helper.
#[derive(Clone, Debug)]
pub struct ProxyClient {
    proxy_addr: SocketAddr,
    backend_addr: SocketAddr,
    auth: ProxyAuth,
}

impl ProxyClient {
    /// Create a new proxy client helper.
    pub fn new(proxy_addr: SocketAddr, backend_addr: SocketAddr) -> Self {
        Self {
            proxy_addr,
            backend_addr,
            auth: ProxyAuth::None,
        }
    }

    /// Set auth to match proxy server requirements.
    pub fn with_auth(mut self, auth: ProxyAuth) -> Self {
        self.auth = auth;
        self
    }

    /// Connect to proxy and send optional auth preface.
    pub fn connect(&self) -> Result<TcpStream, SynError> {
        let mut stream = TcpStream::connect(self.proxy_addr)
            .map_err(|e| SynError::connection_error(e.to_string()))?;

        if let Some(auth_header) = self.auth.encode_header() {
            let request = format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\nAuthorization: {}\r\n\r\n",
                self.backend_addr, self.backend_addr, auth_header
            );
            stream
                .write_all(request.as_bytes())
                .map_err(|e| SynError::connection_error(e.to_string()))?;
        }

        Ok(stream)
    }

    /// Convenience helper for request/response payload exchange.
    pub fn send_and_receive(&self, payload: &[u8]) -> Result<Vec<u8>, SynError> {
        let mut stream = self.connect()?;
        stream
            .write_all(payload)
            .map_err(|e| SynError::connection_error(e.to_string()))?;

        let mut buf = vec![0u8; payload.len().max(1) * 2];
        let read = stream
            .read(&mut buf)
            .map_err(|e| SynError::connection_error(e.to_string()))?;
        buf.truncate(read);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_auth_none() {
        let auth = ProxyAuth::None;
        assert!(auth.validate("any", "thing"));
        assert!(auth.encode_header().is_none());
    }

    #[test]
    fn test_proxy_auth_basic_validation() {
        let auth = ProxyAuth::basic("admin", "password123");
        assert!(auth.validate("admin", "password123"));
        assert!(!auth.validate("admin", "wrong"));
        assert!(!auth.validate("user", "password123"));
    }

    #[test]
    fn test_proxy_auth_basic_encoding() {
        let auth = ProxyAuth::basic("user", "pass");
        let header = auth.encode_header();
        assert!(header.is_some());
        assert!(header.expect("header").starts_with("Basic "));
    }

    #[test]
    fn test_proxy_config() {
        let listen: SocketAddr = "127.0.0.1:8080".parse().expect("listen");
        let backend: SocketAddr = "192.168.1.1:3306".parse().expect("backend");

        let config = ProxyConfig::new(listen, backend)
            .with_auth(ProxyAuth::basic("admin", "secret"))
            .with_buffer_size(16384);

        assert_eq!(config.listen_addr.port(), 8080);
        assert_eq!(config.backend_addr.port(), 3306);
        assert_eq!(config.buffer_size, 16384);
        assert!(matches!(config.auth, ProxyAuth::Basic(_, _)));
    }

    #[test]
    fn test_proxy_auth_handle_updates() {
        let handle = ProxyAuthHandle::new(ProxyAuth::None);
        assert_eq!(handle.current().expect("current"), ProxyAuth::None);

        handle
            .set_basic("admin", "new-secret")
            .expect("set_basic");
        assert!(matches!(
            handle.current().expect("current"),
            ProxyAuth::Basic(user, pass) if user == "admin" && pass == "new-secret"
        ));

        handle.set_none().expect("set_none");
        assert_eq!(handle.current().expect("current"), ProxyAuth::None);
    }

    #[test]
    fn parse_http_auth_bytes_extracts_trailing_payload() {
        // dXNlcjpwYXNz is base64("user:pass")
        let raw = b"CONNECT backend:80 HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\nHELLO";
        let auth = ProxyAuth::basic("user", "pass");
        let result = parse_http_auth_from_bytes(raw, &auth).expect("auth ok");
        assert_eq!(result, b"HELLO");
    }

    #[test]
    fn parse_http_auth_bytes_rejects_bad_credentials() {
        // d3Jvbmc= is base64("wrong")
        let raw = b"CONNECT backend:80 HTTP/1.1\r\nAuthorization: Basic d3Jvbmc=\r\n\r\n";
        let auth = ProxyAuth::basic("user", "pass");
        assert!(parse_http_auth_from_bytes(raw, &auth).is_err());
    }

    #[test]
    fn parse_http_auth_bytes_no_auth_header() {
        let raw = b"CONNECT backend:80 HTTP/1.1\r\nHost: backend\r\n\r\n";
        let auth = ProxyAuth::basic("user", "pass");
        assert!(parse_http_auth_from_bytes(raw, &auth).is_err());
    }
}

mod base64 {
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut output = String::new();

        for chunk in bytes.chunks(3) {
            let b1 = chunk[0];
            let b2 = if chunk.len() > 1 { chunk[1] } else { 0 };
            let b3 = if chunk.len() > 2 { chunk[2] } else { 0 };

            let n = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);

            output.push(BASE64_CHARS[((n >> 18) & 0x3F) as usize] as char);
            output.push(BASE64_CHARS[((n >> 12) & 0x3F) as usize] as char);

            if chunk.len() > 1 {
                output.push(BASE64_CHARS[((n >> 6) & 0x3F) as usize] as char);
            } else {
                output.push('=');
            }

            if chunk.len() > 2 {
                output.push(BASE64_CHARS[(n & 0x3F) as usize] as char);
            } else {
                output.push('=');
            }
        }

        output
    }

    pub fn decode(input: &str) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();
        let input = input.trim_end_matches('=');
        let mut n = 0u32;
        let mut bits = 0;

        for c in input.bytes() {
            let val = if c.is_ascii_uppercase() {
                c - b'A'
            } else if c.is_ascii_lowercase() {
                c - b'a' + 26
            } else if c.is_ascii_digit() {
                c - b'0' + 52
            } else if c == b'+' {
                62
            } else if c == b'/' {
                63
            } else {
                return Err("Invalid base64 character".to_string());
            } as u32;

            n = (n << 6) | val;
            bits += 6;

            if bits >= 8 {
                bits -= 8;
                output.push(((n >> bits) & 0xFF) as u8);
            }
        }

        Ok(output)
    }
}
