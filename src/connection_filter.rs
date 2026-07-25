// Connection filter trait for custom authentication/authorization
// 
// Allows servers to implement custom logic to accept or reject connections
// based on metadata like peer address, TLS status, etc.

use std::sync::Arc;

use crate::handler::Connection;
use crate::SynError;

/// Trait for custom connection filtering/authentication
/// 
/// Implement this trait to provide custom logic for accepting or rejecting
/// connections based on connection metadata.
/// 
/// # Example
/// 
/// ```ignore
/// struct IpWhitelist(Vec<IpAddr>);
/// 
/// impl ConnectionFilter for IpWhitelist {
///     fn filter(&self, conn: &Connection) -> Result<(), SynError> {
///         if self.0.contains(&conn.metadata.peer_addr.ip()) {
///             Ok(())
///         } else {
///             Err(SynError::unauthorized("IP not whitelisted"))
///         }
///     }
/// }
/// ```
pub trait ConnectionFilter: Send + Sync {
    /// Evaluate the connection and return Ok if accepted, Err if rejected
    fn filter(&self, conn: &Connection) -> Result<(), SynError>;
}

/// Type alias for a boxed connection filter
pub type BoxedConnectionFilter = Arc<dyn ConnectionFilter>;

/// Simple IP whitelist filter
pub struct IpWhitelistFilter {
    allowed_ips: Vec<std::net::IpAddr>,
}

impl IpWhitelistFilter {
    /// Create a new IP whitelist filter
    pub fn new(allowed_ips: Vec<std::net::IpAddr>) -> Self {
        Self { allowed_ips }
    }
}

impl ConnectionFilter for IpWhitelistFilter {
    fn filter(&self, conn: &Connection) -> Result<(), SynError> {
        if self.allowed_ips.contains(&conn.metadata().peer_addr.ip()) {
            Ok(())
        } else {
               Err(SynError::runtime("Connection from IP not in whitelist"))
        }
    }
}

/// Simple IP blocklist filter
pub struct IpBlocklistFilter {
    blocked_ips: Vec<std::net::IpAddr>,
}

impl IpBlocklistFilter {
    /// Create a new IP blocklist filter
    pub fn new(blocked_ips: Vec<std::net::IpAddr>) -> Self {
        Self { blocked_ips }
    }
}

impl ConnectionFilter for IpBlocklistFilter {
    fn filter(&self, conn: &Connection) -> Result<(), SynError> {
        if self.blocked_ips.contains(&conn.metadata().peer_addr.ip()) {
               Err(SynError::runtime("Connection from blocked IP"))
        } else {
            Ok(())
        }
    }
}

/// TLS-only filter (reject non-TLS connections)
pub struct TlsOnlyFilter;

impl ConnectionFilter for TlsOnlyFilter {
    fn filter(&self, conn: &Connection) -> Result<(), SynError> {
        if conn.metadata().tls {
            Ok(())
        } else {
               Err(SynError::runtime("TLS required for this connection"))
        }
    }
}

/// Combined filter that runs multiple filters (all must pass)
pub struct CompositeFilter {
    filters: Vec<BoxedConnectionFilter>,
}

impl CompositeFilter {
    /// Create a new composite filter with no filters
    pub fn new() -> Self {
        Self { filters: Vec::new() }
    }

    /// Add a filter to this composite (returns self for chaining)
    pub fn add_filter(mut self, filter: BoxedConnectionFilter) -> Self {
        self.filters.push(filter);
        self
    }
}

impl Default for CompositeFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionFilter for CompositeFilter {
    fn filter(&self, conn: &Connection) -> Result<(), SynError> {
        for filter in &self.filters {
            filter.filter(conn)?;
        }
        Ok(())
    }
}
