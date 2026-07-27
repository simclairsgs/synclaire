use std::collections::HashSet;
use std::sync::Arc;

use crate::handler::Connection;
use crate::SynError;

pub trait ConnectionFilter: Send + Sync {
    fn filter(&self, conn: &Connection) -> Result<(), SynError>;
}

pub type BoxedConnectionFilter = Arc<dyn ConnectionFilter>;

pub struct IpWhitelistFilter {
    allowed_ips: HashSet<std::net::IpAddr>,
}

impl IpWhitelistFilter {
    pub fn new(allowed_ips: impl IntoIterator<Item = std::net::IpAddr>) -> Self {
        Self {
            allowed_ips: allowed_ips.into_iter().collect(),
        }
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

pub struct IpBlocklistFilter {
    blocked_ips: HashSet<std::net::IpAddr>,
}

impl IpBlocklistFilter {
    pub fn new(blocked_ips: impl IntoIterator<Item = std::net::IpAddr>) -> Self {
        Self {
            blocked_ips: blocked_ips.into_iter().collect(),
        }
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

pub struct CompositeFilter {
    filters: Vec<BoxedConnectionFilter>,
}

impl CompositeFilter {
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

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
