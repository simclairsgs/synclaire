pub mod ip_ban;
pub mod rate_limiter;
pub mod slow_loris;
pub mod stack;
pub mod syn_guard;
pub mod throttle;

use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use crate::SynError;

pub use ip_ban::{IpBan, IpBanConfig};
pub use rate_limiter::{RateLimiter, RateLimiterConfig};
pub use slow_loris::{SlowLoris, SlowLorisConfig};
pub use stack::{Allowlist, GuardSession, GuardStack, GuardStackBuilder};
pub use syn_guard::{SynGuard, SynGuardConfig};
pub use throttle::{Throttle, ThrottleConfig};

#[derive(Clone, Debug)]
pub struct UdpAmplificationConfig {
    pub reject_malformed_tcp_probes: bool,
    pub minimum_probe_bytes: usize,
}

impl Default for UdpAmplificationConfig {
    fn default() -> Self {
        Self {
            reject_malformed_tcp_probes: true,
            minimum_probe_bytes: 4,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GuardContext {
    pub peer_addr: SocketAddr,
    pub peer_ip: IpAddr,
    pub local_addr: Option<SocketAddr>,
    pub tls: bool,
    pub tls_server_name: Option<String>,
    pub connected_at: Instant,
}

impl GuardContext {
    pub fn new(peer_addr: SocketAddr, local_addr: Option<SocketAddr>, tls: bool) -> Self {
        Self {
            peer_ip: peer_addr.ip(),
            peer_addr,
            local_addr,
            tls,
            tls_server_name: None,
            connected_at: Instant::now(),
        }
    }
}

#[derive(Debug)]
pub enum GuardDecision {
    Allow,
    Deny(SynError),
}

impl GuardDecision {
    pub fn allow() -> Self {
        Self::Allow
    }

    pub fn deny(error: SynError) -> Self {
        Self::Deny(error)
    }
}

#[derive(Debug)]
pub enum GuardEventKind {
    Reserve,
    Established,
    Payload,
    Activity,
    Close,
}

#[derive(Debug)]
pub struct GuardEvent {
    pub guard: &'static str,
    pub kind: GuardEventKind,
    pub peer_addr: SocketAddr,
    pub decision: GuardDecision,
    pub detail: String,
    pub occurred_at: Instant,
}

pub trait Guard: Send + Sync {
    fn name(&self) -> &'static str;

    fn on_reserve(&self, _context: &GuardContext) -> Result<(), SynError> {
        Ok(())
    }

    fn on_established(&self, _context: &GuardContext) -> Result<(), SynError> {
        Ok(())
    }

    fn on_payload(&self, _context: &GuardContext, _payload: &[u8]) -> Result<(), SynError> {
        Ok(())
    }

    fn on_activity(&self, _context: &GuardContext) -> Result<(), SynError> {
        Ok(())
    }

    fn on_close(&self, _context: &GuardContext) {}
}

pub trait GuardObserver: Send + Sync {
    fn on_event(&self, event: GuardEvent);
}

impl<F> GuardObserver for F
where
    F: Fn(GuardEvent) + Send + Sync,
{
    fn on_event(&self, event: GuardEvent) {
        (self)(event);
    }
}

pub fn event_detail(duration: Duration, message: &str) -> String {
    format!("{message} after {:?}", duration)
}

#[derive(Clone, Debug)]
pub struct UdpAmplificationGuard {
    config: UdpAmplificationConfig,
}

impl UdpAmplificationGuard {
    pub fn new(config: UdpAmplificationConfig) -> Self {
        Self { config }
    }
}

impl Guard for UdpAmplificationGuard {
    fn name(&self) -> &'static str {
        "udp_amplification"
    }

    fn on_payload(&self, _context: &GuardContext, payload: &[u8]) -> Result<(), SynError> {
        if self.config.reject_malformed_tcp_probes
            && payload.len() < self.config.minimum_probe_bytes
        {
            return Err(SynError::malformed_probe(
                "payload too small to look like a real TCP conversation",
            ));
        }

        if self.config.reject_malformed_tcp_probes && payload.first().is_some_and(|byte| *byte == 0)
        {
            return Err(SynError::malformed_probe(
                "first byte looks suspiciously empty",
            ));
        }

        Ok(())
    }
}
