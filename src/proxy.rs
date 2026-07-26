use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::metrics::MetricsCollector;
use crate::load_balancer::BackendPool;
use crate::routing::{RouteAction, RoutingTable};

use crate::config::{GuardStackConfig, TlsConfig};
use crate::guard::GuardContext;
use crate::server::build_guard_stack;
use crate::SynError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyAuth {
    None,
    Basic(String, String),
}

impl ProxyAuth {
    pub fn basic(username: &str, password: &str) -> Self {
        Self::Basic(username.to_string(), password.to_string())
    }

    pub fn validate(&self, username: &str, password: &str) -> bool {
        match self {
            ProxyAuth::None => true,
            ProxyAuth::Basic(user, pass) => username == user && password == pass,
        }
    }

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

#[derive(Clone, Debug)]
pub struct ProxyAuthHandle {
    inner: Arc<RwLock<ProxyAuth>>,
}

impl ProxyAuthHandle {
    pub fn new(initial: ProxyAuth) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial)),
        }
    }

    pub fn current(&self) -> Result<ProxyAuth, SynError> {
        Ok(self.inner.read().clone())
    }

    pub fn set(&self, auth: ProxyAuth) -> Result<(), SynError> {
        *self.inner.write() = auth;
        Ok(())
    }

    pub fn set_none(&self) -> Result<(), SynError> {
        self.set(ProxyAuth::None)
    }

    pub fn set_basic(&self, username: &str, password: &str) -> Result<(), SynError> {
        self.set(ProxyAuth::basic(username, password))
    }
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub backend_addr: SocketAddr,
    pub auth: ProxyAuth,
    pub buffer_size: usize,
    pub connection_timeout: std::time::Duration,
    pub guards: GuardStackConfig,
    pub tls_offload: Option<TlsConfig>,
    pub routing: Option<Arc<RoutingTable>>,
    pub backend_pool: Option<Arc<BackendPool>>,
}

impl ProxyConfig {
    pub fn new(listen_addr: SocketAddr, backend_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            backend_addr,
            auth: ProxyAuth::None,
            buffer_size: 8192,
            connection_timeout: std::time::Duration::from_secs(30),
            guards: GuardStackConfig::default(),
            tls_offload: None,
            routing: None,
            backend_pool: None,
        }
    }

    pub fn with_connection_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    pub fn with_auth(mut self, auth: ProxyAuth) -> Self {
        self.auth = auth;
        self
    }

    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    pub fn with_guards(mut self, guards: GuardStackConfig) -> Self {
        self.guards = guards;
        self
    }

    /// Async only — sync proxy rejects this with `UnsupportedFeature`.
    pub fn with_tls_offload(mut self, tls: TlsConfig) -> Self {
        self.tls_offload = Some(tls);
        self
    }

    pub fn with_routing(mut self, routing: Arc<RoutingTable>) -> Self {
        self.routing = Some(routing);
        self
    }

    pub fn with_backend_pool(mut self, pool: Arc<BackendPool>) -> Self {
        self.backend_pool = Some(pool);
        self
    }
}

fn parse_http_auth_from_bytes(data: &[u8], auth: &ProxyAuth) -> Result<Vec<u8>, SynError> {
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(data.len());

    let headers_raw = &data[..header_end];
    let headers = String::from_utf8_lossy(headers_raw);

    for line in headers.lines().skip(1) {
        if let Some(value) = line.strip_prefix("Authorization: ") {
            if auth.validate_header(value.trim()) {
                return Ok(data[header_end..].to_vec());
            }
            return Err(SynError::authentication_error("Invalid credentials"));
        }
    }

    Err(SynError::authentication_error("Authorization required"))
}

#[derive(Clone, Debug)]
pub struct TcpProxy {
    config: ProxyConfig,
    auth_handle: Option<ProxyAuthHandle>,
}

impl TcpProxy {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            auth_handle: None,
        }
    }

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

    pub fn forward(&self, client: TcpStream) -> Result<(), SynError> {
        self.forward_to(client, None)
    }

    pub fn forward_to(&self, mut client: TcpStream, override_backend: Option<SocketAddr>) -> Result<(), SynError> {
        let timeout = self.config.connection_timeout;
        client.set_read_timeout(Some(timeout)).ok();
        client.set_write_timeout(Some(timeout)).ok();

        let effective_auth = self.effective_auth()?;

        let trailing_payload = if matches!(effective_auth, ProxyAuth::Basic(_, _)) {
            self.validate_http_auth_stream(&mut client, &effective_auth)?
        } else {
            Vec::new()
        };

        let backend_addr = override_backend.unwrap_or(self.config.backend_addr);
        let mut backend = TcpStream::connect_timeout(&backend_addr.into(), timeout)
            .map_err(|e| SynError::connection_error(e.to_string()))?;
        backend.set_read_timeout(Some(timeout)).ok();
        backend.set_write_timeout(Some(timeout)).ok();

        // Write any payload the client sent immediately after the CONNECT
        // headers before handing off to bidirectional forwarding.
        if !trailing_payload.is_empty() {
            backend.write_all(&trailing_payload).map_err(|e| {
                SynError::connection_error(format!("Failed to write trailing payload to backend: {}", e))
            })?;
        }

        self.forward_bidirectional(client, backend)
    }

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

            let previous_len = data.len();
            data.extend_from_slice(&chunk[..n]);

            let search_from = previous_len.saturating_sub(3);
            if data[search_from..].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }

            if data.len() > 64 * 1024 {
                return Err(SynError::authentication_error("proxy auth headers too large"));
            }
        }

        parse_http_auth_from_bytes(&data, auth)
    }

    fn forward_bidirectional(&self, mut client: TcpStream, mut backend: TcpStream) -> Result<(), SynError> {
        use std::thread;

        let mut client_for_reverse = client.try_clone().map_err(|e| {
            SynError::connection_error(format!("Failed to clone client for reverse: {}", e))
        })?;

        let mut backend_for_forward = backend.try_clone().map_err(|e| {
            SynError::connection_error(format!("Failed to clone backend for forward: {}", e))
        })?;

        let buffer_size = self.config.buffer_size;

        let client_to_backend = thread::spawn(move || {
            let mut buf = vec![0u8; buffer_size];
            loop {
                match client.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if backend_for_forward.write_all(&buf[..n]).is_err() {
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
                match backend.read(&mut buf) {
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

pub struct ProxyServer {
    config: ProxyConfig,
    auth_handle: Option<ProxyAuthHandle>,
    metrics: Option<Arc<MetricsCollector>>,
}

impl ProxyServer {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            auth_handle: None,
            metrics: None,
        }
    }

    pub fn with_auth_handle(mut self, auth_handle: ProxyAuthHandle) -> Self {
        self.auth_handle = Some(auth_handle);
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<MetricsCollector>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn auth_handle(&self) -> Option<ProxyAuthHandle> {
        self.auth_handle.clone()
    }

    pub fn run(&self) -> Result<(), SynError> {
        if self.config.tls_offload.as_ref().is_some_and(|tls| tls.enabled) {
            return Err(SynError::UnsupportedFeature(
                "sync proxy TLS offload is not implemented yet",
            ));
        }

        let listener = TcpListener::bind(self.config.listen_addr)?;
        let guards = build_guard_stack(&self.config.guards);
        let mut proxy = TcpProxy::new(self.config.clone());
        if let Some(handle) = &self.auth_handle {
            proxy = proxy.with_auth_handle(handle.clone());
        }
        let proxy = Arc::new(proxy);
        let actual_listen_addr = listener.local_addr().unwrap_or(self.config.listen_addr);

        log::info!(
            "proxy server listening on {} forwarding to {}",
            actual_listen_addr,
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
                                                    let _ = stream.shutdown(std::net::Shutdown::Both);
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
                                                let _ = stream.shutdown(std::net::Shutdown::Both);
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

            let metrics = self.metrics.clone();
            let proxy = Arc::clone(&proxy);

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

#[cfg(feature = "async")]
pub struct AsyncProxyServer {
    config: ProxyConfig,
    auth_handle: Option<ProxyAuthHandle>,
    metrics: Option<Arc<MetricsCollector>>,
}

#[cfg(feature = "async")]
impl AsyncProxyServer {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            auth_handle: None,
            metrics: None,
        }
    }

    pub fn with_auth_handle(mut self, auth_handle: ProxyAuthHandle) -> Self {
        self.auth_handle = Some(auth_handle);
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<MetricsCollector>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub async fn run(&self) -> Result<(), SynError> {
        use tokio::net::TcpListener;
        use tokio::io::AsyncWriteExt;

        let listener = TcpListener::bind(self.config.listen_addr).await?;
        let guards = build_guard_stack(&self.config.guards);
        let actual_listen_addr = listener.local_addr().unwrap_or(self.config.listen_addr);

        log::info!(
            "async proxy server listening on {} forwarding to {}",
            actual_listen_addr,
            self.config.backend_addr
        );

        loop {
            let (mut stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    log::warn!("async proxy accept error: {}", e);
                    continue;
                }
            };
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
                                                    let _ = stream.shutdown().await;
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
                                                let _ = stream.shutdown().await;
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
            let timeout = config.connection_timeout;
            let auth_handle = self.auth_handle.clone();
            let metrics = self.metrics.clone();

            tokio::spawn(async move {
                match tokio::time::timeout(
                    timeout,
                    forward_async_connection(stream, config, auth_handle, backend_override),
                ).await {
                    Ok(Err(error)) => {
                        log::warn!("[{}] async proxy forwarding error: {}", peer_addr, error);
                    }
                    Err(_) => {
                        log::debug!("[{}] async proxy connection timed out after {:?}", peer_addr, timeout);
                    }
                    Ok(Ok(())) => {}
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

            let previous_len = data.len();
            data.extend_from_slice(&chunk[..read]);
            let search_from = previous_len.saturating_sub(3);
            if let Some(index) = data[search_from..].windows(4).position(|w| w == b"\r\n\r\n") {
                break search_from + index + 4;
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
    let mut backend = tokio::time::timeout(
        config.connection_timeout,
        tokio::net::TcpStream::connect(backend_addr),
    )
        .await
        .map_err(|_| SynError::connection_error(format!(
            "backend connect to {} timed out after {:?}", backend_addr, config.connection_timeout
        )))?
        .map_err(|e| SynError::connection_error(e.to_string()))?;

    if let Some(tls) = &config.tls_offload {
        if tls.enabled {
            #[cfg(any(feature = "rustls-backend", feature = "aws-lc-backend"))]
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

            #[cfg(not(any(feature = "rustls-backend", feature = "aws-lc-backend")))]
            {
                let _ = stream;
                return Err(SynError::UnsupportedFeature(
                    "proxy TLS offload requires rustls-backend or aws-lc-backend feature",
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

#[derive(Clone, Debug)]
pub struct ProxyClient {
    proxy_addr: SocketAddr,
    backend_addr: SocketAddr,
    auth: ProxyAuth,
}

impl ProxyClient {
    pub fn new(proxy_addr: SocketAddr, backend_addr: SocketAddr) -> Self {
        Self {
            proxy_addr,
            backend_addr,
            auth: ProxyAuth::None,
        }
    }

    pub fn with_auth(mut self, auth: ProxyAuth) -> Self {
        self.auth = auth;
        self
    }

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
        let mut output = String::with_capacity(((bytes.len() + 2) / 3) * 4);

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
        let input = input.trim_end_matches('=');
        let mut output = Vec::with_capacity((input.len() * 3) / 4 + 3);
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

    #[cfg(test)]
    mod tests {
        use super::*;

        // RFC 4648 §10 test vectors
        #[test]
        fn encode_rfc4648_vectors() {
            assert_eq!(encode(""), "");
            assert_eq!(encode("f"), "Zg==");
            assert_eq!(encode("fo"), "Zm8=");
            assert_eq!(encode("foo"), "Zm9v");
            assert_eq!(encode("foob"), "Zm9vYg==");
            assert_eq!(encode("fooba"), "Zm9vYmE=");
            assert_eq!(encode("foobar"), "Zm9vYmFy");
        }

        #[test]
        fn decode_rfc4648_vectors() {
            assert_eq!(decode("").unwrap(), b"");
            assert_eq!(decode("Zg==").unwrap(), b"f");
            assert_eq!(decode("Zm8=").unwrap(), b"fo");
            assert_eq!(decode("Zm9v").unwrap(), b"foo");
            assert_eq!(decode("Zm9vYg==").unwrap(), b"foob");
            assert_eq!(decode("Zm9vYmE=").unwrap(), b"fooba");
            assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
        }

        #[test]
        fn roundtrip() {
            let cases = ["", "a", "ab", "abc", "abcd", "hello world", "user:pass"];
            for case in &cases {
                let encoded = encode(case);
                let decoded = decode(&encoded).unwrap();
                assert_eq!(decoded, case.as_bytes(), "roundtrip failed for {:?}", case);
            }
        }
    }
}
