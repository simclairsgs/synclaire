//! synclaire: where every connection is handled with clarity.

pub mod client;
pub mod config;
pub mod error;
pub mod guard;
pub mod handler;
pub mod load_balancer;
pub mod metrics;
pub mod proxy;
pub mod routing;
pub mod server;
pub mod tls;
pub mod connection_filter;
pub(crate) mod cleanup;

pub use config::{AcceptMode, ClientConfig, GuardStackConfig, PemSource, ServerConfig, TlsConfig};
pub use error::SynError;
pub use guard::{IpBan, IpBanConfig, RateLimiter, RateLimiterConfig, SlowLorisConfig, SynGuardConfig, ThrottleConfig};
pub use load_balancer::{Backend, BackendPool, LoadBalancerStrategy, StickyKey};
pub use handler::{Connection, ConnectionMetadata, ConnectionStream};
#[cfg(feature = "async")]
pub use handler::AsyncStream;
#[cfg(any(feature = "async", feature = "sync"))]
pub use handler::ConnectionHandler;
pub use metrics::{ConnectionMetrics, LoggingMetricsCallback, MetricsCallback, MetricsCollector};
pub use proxy::{ProxyAuth, ProxyAuthHandle, ProxyClient, ProxyConfig, ProxyServer, TcpProxy};
pub use routing::{IpGroup, IpPrefix, RouteAction, RoutingRule, RoutingTable};
#[cfg(feature = "async")]
pub use proxy::AsyncProxyServer;
pub use connection_filter::{
	ConnectionFilter, BoxedConnectionFilter, IpWhitelistFilter, IpBlocklistFilter, 
	TlsOnlyFilter, CompositeFilter
};

#[cfg(feature = "sync")]
pub use handler::SyncStream;
#[cfg(feature = "sync")]
pub use handler::SyncConnectionHandler;

pub type Result<T> = std::result::Result<T, SynError>;

#[cfg(feature = "async")]
pub use server::async_server::{AsyncServer, AsyncServerShutdown};

#[cfg(feature = "sync")]
pub use server::sync_server::{SyncServer, SyncServerShutdown, SyncShutdownSignal};

#[cfg(feature = "async")]
pub use client::AsyncClient;

#[cfg(feature = "sync")]
pub use client::SyncClient;