use std::{net::SocketAddr, path::PathBuf, time::Duration};

use crate::{
    guard::{
        IpBanConfig, RateLimiterConfig, SlowLorisConfig, SynGuardConfig, ThrottleConfig,
        UdpAmplificationConfig,
    },
};

/// Controls what connection types the server will accept on its bound port.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum AcceptMode {
    /// Accept plain TCP only (default).
    #[default]
    Tcp,
    /// Accept TLS only. TLS config must be populated.
    Tls,
    /// Auto-detect per connection by peeking at the first byte.
    /// Connections that start with 0x16 (TLS ClientHello) get a TLS handshake;
    /// everything else is treated as plain TCP.
    /// TLS config must be populated for TLS connections to succeed.
    Mixed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PemSource {
    File { path: PathBuf },
    Inline { pem: String },
}

impl PemSource {
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File { path: path.into() }
    }

    pub fn inline_pem(pem: impl Into<String>) -> Self {
        Self::Inline { pem: pem.into() }
    }

    pub fn from_pem_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self::Inline {
            pem: String::from_utf8_lossy(bytes.as_ref()).into_owned(),
        }
    }

    pub fn from_file(path: impl Into<PathBuf>) -> Self {
        Self::file(path)
    }
}

#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub certificate_chain: Option<PemSource>,
    pub private_key: Option<PemSource>,
    pub client_certificate_chain: Option<PemSource>,
    pub client_private_key: Option<PemSource>,
    pub trust_anchors: Vec<PemSource>,
    pub alpn_protocols: Vec<String>,
    pub verify_peer: bool,
    pub require_client_auth: bool,
    pub prefer_aws_lc: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_name: None,
            certificate_chain: None,
            private_key: None,
            client_certificate_chain: None,
            client_private_key: None,
            trust_anchors: Vec::new(),
            alpn_protocols: vec!["synclaire/1".to_string()],
            verify_peer: true,
            require_client_auth: false,
            prefer_aws_lc: false,
        }
    }
}

impl TlsConfig {
    pub fn builder() -> TlsConfigBuilder {
        TlsConfigBuilder::default()
    }

    pub fn disabled() -> Self {
        Self::default()
    }
}

#[derive(Default)]
pub struct TlsConfigBuilder {
    config: TlsConfig,
}

impl TlsConfigBuilder {
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    pub fn server_name(mut self, server_name: impl Into<String>) -> Self {
        self.config.server_name = Some(server_name.into());
        self
    }

    pub fn certificate_chain(mut self, source: PemSource) -> Self {
        self.config.certificate_chain = Some(source);
        self
    }

    pub fn private_key(mut self, source: PemSource) -> Self {
        self.config.private_key = Some(source);
        self
    }

    pub fn client_certificate_chain(mut self, source: PemSource) -> Self {
        self.config.client_certificate_chain = Some(source);
        self
    }

    pub fn client_private_key(mut self, source: PemSource) -> Self {
        self.config.client_private_key = Some(source);
        self
    }

    pub fn trust_anchor(mut self, source: PemSource) -> Self {
        self.config.trust_anchors.push(source);
        self
    }

    pub fn alpn_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.config.alpn_protocols.push(protocol.into());
        self
    }

    pub fn verify_peer(mut self, verify_peer: bool) -> Self {
        self.config.verify_peer = verify_peer;
        self
    }

    pub fn require_client_auth(mut self, require_client_auth: bool) -> Self {
        self.config.require_client_auth = require_client_auth;
        self
    }

    pub fn prefer_aws_lc(mut self, prefer_aws_lc: bool) -> Self {
        self.config.prefer_aws_lc = prefer_aws_lc;
        self
    }

    pub fn build(self) -> TlsConfig {
        self.config
    }
}

#[derive(Clone, Debug)]
pub struct GuardStackConfig {
    pub rate_limiter: Option<RateLimiterConfig>,
    pub ip_ban: Option<IpBanConfig>,
    pub throttle: Option<ThrottleConfig>,
    pub syn_guard: Option<SynGuardConfig>,
    pub slow_loris: Option<SlowLorisConfig>,
    pub udp_amplification: Option<UdpAmplificationConfig>,
}

impl Default for GuardStackConfig {
    fn default() -> Self {
        Self {
            rate_limiter: None,
            ip_ban: None,
            throttle: None,
            syn_guard: None,
            slow_loris: None,
            udp_amplification: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub worker_threads: usize,
    pub connection_timeout: Duration,
    pub max_connections: usize,
    pub tcp_nodelay: bool,
    pub tls: TlsConfig,
    pub guards: GuardStackConfig,
    pub name: String,
    pub accept_mode: AcceptMode,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:7000".parse().expect("valid default bind address"),
            worker_threads: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            connection_timeout: Duration::from_secs(30),
            max_connections: 100_000,
            tcp_nodelay: true,
            tls: TlsConfig::default(),
            guards: GuardStackConfig::default(),
            name: "synclaire-server".to_string(),
            accept_mode: AcceptMode::Tcp,
        }
    }
}

impl ServerConfig {
    pub fn builder() -> ServerConfigBuilder {
        ServerConfigBuilder::default()
    }
}

#[derive(Default)]
pub struct ServerConfigBuilder {
    config: ServerConfig,
}

impl ServerConfigBuilder {
    pub fn bind_addr(mut self, bind_addr: SocketAddr) -> Self {
        self.config.bind_addr = bind_addr;
        self
    }

    pub fn worker_threads(mut self, worker_threads: usize) -> Self {
        self.config.worker_threads = worker_threads.max(1);
        self
    }

    pub fn connection_timeout(mut self, timeout: Duration) -> Self {
        self.config.connection_timeout = timeout;
        self
    }

    pub fn max_connections(mut self, max_connections: usize) -> Self {
        self.config.max_connections = max_connections.max(1);
        self
    }

    pub fn tcp_nodelay(mut self, tcp_nodelay: bool) -> Self {
        self.config.tcp_nodelay = tcp_nodelay;
        self
    }

    pub fn tls(mut self, tls: TlsConfig) -> Self {
        self.config.tls = tls;
        self
    }

    pub fn guards(mut self, guards: GuardStackConfig) -> Self {
        self.config.guards = guards;
        self
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.config.name = name.into();
        self
    }

    /// Set the accept mode (TCP-only, TLS-only, or mixed auto-detect).
    pub fn accept_mode(mut self, mode: AcceptMode) -> Self {
        self.config.accept_mode = mode;
        self
    }

    pub fn build(self) -> ServerConfig {
        self.config
    }
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub connect_addr: SocketAddr,
    pub connection_timeout: Duration,
    pub tcp_nodelay: bool,
    pub tls: TlsConfig,
    pub name: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            connect_addr: "127.0.0.1:7000".parse().expect("valid default connect address"),
            connection_timeout: Duration::from_secs(10),
            tcp_nodelay: true,
            tls: TlsConfig::default(),
            name: "synclaire-client".to_string(),
        }
    }
}

impl ClientConfig {
    pub fn builder() -> ClientConfigBuilder {
        ClientConfigBuilder::default()
    }
}

#[derive(Default)]
pub struct ClientConfigBuilder {
    config: ClientConfig,
}

impl ClientConfigBuilder {
    pub fn connect_addr(mut self, connect_addr: SocketAddr) -> Self {
        self.config.connect_addr = connect_addr;
        self
    }

    pub fn connection_timeout(mut self, timeout: Duration) -> Self {
        self.config.connection_timeout = timeout;
        self
    }

    pub fn tcp_nodelay(mut self, tcp_nodelay: bool) -> Self {
        self.config.tcp_nodelay = tcp_nodelay;
        self
    }

    pub fn tls(mut self, tls: TlsConfig) -> Self {
        self.config.tls = tls;
        self
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.config.name = name.into();
        self
    }

    pub fn build(self) -> ClientConfig {
        self.config
    }
}