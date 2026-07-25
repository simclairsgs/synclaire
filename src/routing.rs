use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use crate::load_balancer::BackendPool;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpPrefix {
    pub base: IpAddr,
    pub prefix_len: u8,
}

impl IpPrefix {
    pub fn v4(a: u8, b: u8, c: u8, d: u8, prefix_len: u8) -> Self {
        Self {
            base: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            prefix_len,
        }
    }

    pub fn v6(segments: [u16; 8], prefix_len: u8) -> Self {
        let [a, b, c, d, e, f, g, h] = segments;
        Self {
            base: IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)),
            prefix_len,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let (addr_str, prefix_str) = s.split_once('/')?;
        let base = addr_str.parse().ok()?;
        let prefix_len = prefix_str.parse().ok()?;
        Some(Self { base, prefix_len })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(base), IpAddr::V4(ip)) => {
                let bits = self.prefix_len.min(32) as u32;
                if bits == 0 {
                    return true;
                }
                let mask = !0u32 << (32 - bits);
                let base_n = u32::from(base);
                let ip_n = u32::from(ip);
                (base_n & mask) == (ip_n & mask)
            }
            (IpAddr::V6(base), IpAddr::V6(ip)) => {
                let bits = self.prefix_len.min(128) as u128;
                if bits == 0 {
                    return true;
                }
                let mask = !0u128 << (128 - bits);
                let base_n = u128::from(base);
                let ip_n = u128::from(ip);
                (base_n & mask) == (ip_n & mask)
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct IpGroup {
    pub ips: Vec<IpAddr>,
    pub prefixes: Vec<IpPrefix>,
}

impl IpGroup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_ip(mut self, ip: IpAddr) -> Self {
        self.ips.push(ip);
        self
    }

    pub fn add_prefix(mut self, prefix: IpPrefix) -> Self {
        self.prefixes.push(prefix);
        self
    }

    /// Check whether `ip` is a member of this group.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip) || self.prefixes.iter().any(|p| p.contains(ip))
    }
}

#[derive(Clone)]
pub enum RouteAction {
    Forward(SocketAddr),
    Pool(Arc<BackendPool>),
    Reject,
}

#[derive(Clone, Debug)]
pub struct RoutingRule {
    pub name: String,
    pub source_group: Option<String>,
    pub source_ips: Vec<IpAddr>,
    pub source_port_range: Option<(u16, u16)>,
    pub action: RouteAction,
}

impl RoutingRule {
    pub fn new(name: impl Into<String>, action: RouteAction) -> Self {
        Self {
            name: name.into(),
            source_group: None,
            source_ips: Vec::new(),
            source_port_range: None,
            action,
        }
    }

    pub fn from_group(mut self, group: impl Into<String>) -> Self {
        self.source_group = Some(group.into());
        self
    }

    pub fn from_ips(mut self, ips: impl IntoIterator<Item = IpAddr>) -> Self {
        self.source_ips.extend(ips);
        self
    }

    pub fn from_ip(mut self, ip: IpAddr) -> Self {
        self.source_ips.push(ip);
        self
    }

    pub fn from_port_range(mut self, start: u16, end: u16) -> Self {
        self.source_port_range = Some((start, end));
        self
    }

    pub fn from_port(self, port: u16) -> Self {
        self.from_port_range(port, port)
    }

    fn matches(&self, peer: SocketAddr, groups: &HashMap<String, IpGroup>) -> bool {
        let peer_ip = peer.ip();
        let peer_port = peer.port();

        // Source port check.
        if let Some((start, end)) = self.source_port_range {
            if peer_port < start || peer_port > end {
                return false;
            }
        }

        // IP criteria: at least one of source_group or source_ips must match, or both are empty.
        let has_ip_criteria = self.source_group.is_some() || !self.source_ips.is_empty();

        if has_ip_criteria {
            let in_exact = self.source_ips.contains(&peer_ip);
            let in_group = self.source_group.as_ref().is_some_and(|g| {
                groups.get(g).is_some_and(|group| group.contains(peer_ip))
            });

            if !in_exact && !in_group {
                return false;
            }
        }

        true
    }
}

/// Rules evaluated top-to-bottom; first match wins, otherwise `default_action`.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    inner: Arc<RwLock<RoutingTableInner>>,
}

#[derive(Debug)]
struct RoutingTableInner {
    groups: HashMap<String, IpGroup>,
    rules: Vec<RoutingRule>,
    default_action: RouteAction,
}

impl RoutingTable {
    pub fn new(default_action: RouteAction) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RoutingTableInner {
                groups: HashMap::new(),
                rules: Vec::new(),
                default_action,
            })),
        }
    }

    pub fn add_group(&self, name: impl Into<String>, group: IpGroup) {
        if let Ok(mut inner) = self.inner.write() {
            inner.groups.insert(name.into(), group);
        }
    }

    pub fn add_rule(&self, rule: RoutingRule) {
        if let Ok(mut inner) = self.inner.write() {
            inner.rules.push(rule);
        }
    }

    pub fn prepend_rule(&self, rule: RoutingRule) {
        if let Ok(mut inner) = self.inner.write() {
            inner.rules.insert(0, rule);
        }
    }

    pub fn set_default(&self, action: RouteAction) {
        if let Ok(mut inner) = self.inner.write() {
            inner.default_action = action;
        }
    }

    pub fn resolve(&self, peer: SocketAddr) -> RouteAction {
        let inner = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return RouteAction::Reject,
        };

        for rule in &inner.rules {
            if rule.matches(peer, &inner.groups) {
                log::debug!(
                    "[routing] peer {} matched rule '{}' → {:?}",
                    peer,
                    rule.name,
                    rule.action
                );
                return rule.action.clone();
            }
        }

        log::debug!("[routing] peer {} → default action", peer);
        inner.default_action.clone()
    }
}

// Implement Debug for RouteAction for the log above.
impl std::fmt::Debug for RouteAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteAction::Forward(addr) => write!(f, "Forward({})", addr),
            RouteAction::Pool(pool) => write!(f, "Pool({} backends)", pool.len()),
            RouteAction::Reject => write!(f, "Reject"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    fn backend(port: u16) -> RouteAction {
        RouteAction::Forward(v4(10, 0, 0, 1, port))
    }

    #[test]
    fn test_ip_prefix_v4_match() {
        let prefix = IpPrefix::v4(192, 168, 1, 0, 24);
        assert!(prefix.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(!prefix.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
        assert!(!prefix.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_ip_prefix_parse() {
        let prefix = IpPrefix::parse("10.0.0.0/8").expect("parse");
        assert!(prefix.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!prefix.contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn test_ip_group_membership() {
        let internal = IpGroup::new()
            .add_prefix(IpPrefix::v4(10, 0, 0, 0, 8))
            .add_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5)));

        assert!(internal.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))));
        assert!(internal.contains(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5))));
        assert!(!internal.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn test_routing_table_first_match_wins() {
        let table = RoutingTable::new(backend(9000));
        table.add_group(
            "internal",
            IpGroup::new().add_prefix(IpPrefix::v4(10, 0, 0, 0, 8)),
        );

        table.add_rule(
            RoutingRule::new("internal-to-primary", backend(8001))
                .from_group("internal"),
        );
        table.add_rule(
            RoutingRule::new("all-to-secondary", backend(8002)),
        );

        let internal_peer = v4(10, 0, 0, 5, 12345);
        let external_peer = v4(1, 2, 3, 4, 12345);

        assert!(matches!(
            table.resolve(internal_peer),
            RouteAction::Forward(addr) if addr.port() == 8001
        ));
        assert!(matches!(
            table.resolve(external_peer),
            RouteAction::Forward(addr) if addr.port() == 8002
        ));
    }

    #[test]
    fn test_routing_table_port_filter() {
        let table = RoutingTable::new(backend(9000));
        table.add_rule(
            RoutingRule::new("admin-port-to-mgmt", backend(8888))
                .from_port(9999),
        );

        assert!(matches!(
            table.resolve(v4(1, 2, 3, 4, 9999)),
            RouteAction::Forward(addr) if addr.port() == 8888
        ));
        assert!(matches!(
            table.resolve(v4(1, 2, 3, 4, 1234)),
            RouteAction::Forward(addr) if addr.port() == 9000
        ));
    }

    #[test]
    fn test_routing_table_reject() {
        let table = RoutingTable::new(RouteAction::Reject);
        table.add_group(
            "trusted",
            IpGroup::new().add_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        );
        table.add_rule(
            RoutingRule::new("allow-trusted", backend(8080))
                .from_group("trusted"),
        );

        assert!(matches!(
            table.resolve(v4(127, 0, 0, 1, 9999)),
            RouteAction::Forward(_)
        ));
        assert!(matches!(
            table.resolve(v4(8, 8, 8, 8, 9999)),
            RouteAction::Reject
        ));
    }

    #[test]
    fn test_dynamic_rule_prepend() {
        let table = RoutingTable::new(backend(9000));
        table.add_rule(RoutingRule::new("default-backend", backend(8001)));

        // Prepend a higher-priority emergency-block rule.
        table.prepend_rule(
            RoutingRule::new("emergency-block", RouteAction::Reject)
                .from_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        );

        assert!(matches!(
            table.resolve(v4(1, 2, 3, 4, 12345)),
            RouteAction::Reject
        ));
        assert!(matches!(
            table.resolve(v4(5, 6, 7, 8, 12345)),
            RouteAction::Forward(addr) if addr.port() == 8001
        ));
    }
}
