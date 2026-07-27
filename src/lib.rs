//! synclaire: where every connection is handled with clarity.

pub(crate) mod cleanup;
pub mod client;
pub mod config;
pub mod connection_filter;
pub mod error;
pub mod guard;
pub mod handler;
pub mod load_balancer;
pub mod metrics;
pub mod proxy;
pub mod routing;
pub mod server;
pub mod tls;

pub use config::{AcceptMode, ClientConfig, GuardStackConfig, PemSource, ServerConfig, TlsConfig};
pub use connection_filter::{
    BoxedConnectionFilter, CompositeFilter, ConnectionFilter, IpBlocklistFilter, IpWhitelistFilter,
    TlsOnlyFilter,
};
pub use error::SynError;
pub use guard::{
    Allowlist, IpBan, IpBanConfig, RateLimiter, RateLimiterConfig, SlowLorisConfig, SynGuardConfig,
    ThrottleConfig,
};
#[cfg(feature = "async")]
pub use handler::AsyncStream;
#[cfg(any(feature = "async", feature = "sync"))]
pub use handler::ConnectionHandler;
pub use handler::{Connection, ConnectionMetadata, ConnectionStream};
pub use load_balancer::{Backend, BackendPool, LoadBalancerStrategy, StickyKey};
pub use metrics::{ConnectionMetrics, LoggingMetricsCallback, MetricsCallback, MetricsCollector};
#[cfg(feature = "async")]
pub use proxy::AsyncProxyServer;
pub use proxy::{ProxyAuth, ProxyAuthHandle, ProxyClient, ProxyConfig, ProxyServer, TcpProxy};
pub use routing::{IpGroup, IpPrefix, RouteAction, RoutingRule, RoutingTable};

#[cfg(feature = "sync")]
pub use handler::SyncConnectionHandler;
#[cfg(feature = "sync")]
pub use handler::SyncStream;

pub type Result<T> = std::result::Result<T, SynError>;

#[cfg(feature = "async")]
pub use server::async_server::{AsyncServer, AsyncServerShutdown};

#[cfg(feature = "sync")]
pub use server::sync_server::{SyncServer, SyncServerShutdown, SyncShutdownSignal};

#[cfg(feature = "async")]
pub use client::AsyncClient;

#[cfg(feature = "sync")]
pub use client::SyncClient;
