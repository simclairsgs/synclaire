use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use crate::{guard::{Guard, GuardContext}, SynError};

#[derive(Clone, Debug)]
pub struct SynGuardConfig {
    pub max_half_open_per_ip: usize,
    pub max_half_open_global: usize,
    pub backlog_limit: usize,
    pub syn_timeout: Duration,
    /// Maximum number of IPs tracked in the per-IP half-open map.
    pub max_tracked_ips: usize,
}

impl Default for SynGuardConfig {
    fn default() -> Self {
        Self {
            max_half_open_per_ip: 32,
            max_half_open_global: 512,
            backlog_limit: 1_024,
            syn_timeout: Duration::from_secs(5),
            max_tracked_ips: 100_000,
        }
    }
}

#[derive(Default)]
struct HalfOpenState {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
    ip_order: VecDeque<IpAddr>,
    started_at: HashMap<IpAddr, Instant>,
    /// Connections that have passed on_established — used to avoid double-decrementing.
    established: HashSet<SocketAddr>,
}

pub struct SynGuard {
    config: SynGuardConfig,
    state: Mutex<HalfOpenState>,
}

impl SynGuard {
    pub fn new(config: SynGuardConfig) -> Self {
        Self {
            config,
            state: Mutex::new(HalfOpenState::default()),
        }
    }

    fn reserve(&self, ip: IpAddr) -> Result<(), SynError> {
        let mut state = self.state.lock();

        let next_total = state.total + 1;
        let next_ip = state.per_ip.get(&ip).copied().unwrap_or(0) + 1;

        if next_total > self.config.max_half_open_global {
            return Err(SynError::throttled("half-open global", self.config.max_half_open_global));
        }

        if next_ip > self.config.max_half_open_per_ip {
            return Err(SynError::throttled("half-open per-ip", self.config.max_half_open_per_ip));
        }

        // Evict oldest IP entry if we are at the tracking cap (new IP only).
        let is_new_ip = !state.per_ip.contains_key(&ip);
        if is_new_ip && state.per_ip.len() >= self.config.max_tracked_ips {
            if let Some(old_ip) = state.ip_order.pop_front() {
                if let Some(old_count) = state.per_ip.remove(&old_ip) {
                    state.total = state.total.saturating_sub(old_count);
                }
                state.started_at.remove(&old_ip);
            }
        }

        state.total = next_total;
        if is_new_ip {
            state.ip_order.push_back(ip);
        }
        *state.per_ip.entry(ip).or_insert(0) = next_ip;
        state.started_at.entry(ip).or_insert_with(Instant::now);

        Ok(())
    }

    fn establish(&self, addr: SocketAddr) {
        let ip = addr.ip();
        let mut state = self.state.lock();
        if state.total > 0 {
            state.total -= 1;
        }

        if let Some(count) = state.per_ip.get_mut(&ip) {
            if *count > 1 {
                *count -= 1;
            } else {
                state.per_ip.remove(&ip);
                state.started_at.remove(&ip);
            }
        }

        state.established.insert(addr);
    }

    fn close(&self, addr: SocketAddr) {
        let mut state = self.state.lock();
        // Only decrement half-open counter if we never called establish.
        if state.established.remove(&addr) {
            // Was established — counter was already decremented in establish().
            return;
        }
        // Not established — still counted as half-open; decrement now.
        let ip = addr.ip();
        if state.total > 0 {
            state.total -= 1;
        }
        if let Some(count) = state.per_ip.get_mut(&ip) {
            if *count > 1 {
                *count -= 1;
            } else {
                state.per_ip.remove(&ip);
                state.started_at.remove(&ip);
            }
        }
    }
}

impl Guard for SynGuard {
    fn name(&self) -> &'static str {
        "syn_guard"
    }

    fn on_reserve(&self, context: &GuardContext) -> Result<(), SynError> {
        self.reserve(context.peer_ip)
    }

    fn on_established(&self, context: &GuardContext) -> Result<(), SynError> {
        self.establish(context.peer_addr);
        Ok(())
    }

    fn on_activity(&self, context: &GuardContext) -> Result<(), SynError> {
        let state = self.state.lock();
        if let Some(started_at) = state.started_at.get(&context.peer_ip) {
            if started_at.elapsed() > self.config.syn_timeout {
                return Err(SynError::timeout(self.config.syn_timeout, "waiting for a connection to settle"));
            }
        }
        Ok(())
    }

    fn on_close(&self, context: &GuardContext) {
        self.close(context.peer_addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::{Guard, GuardContext};
    use std::net::SocketAddr;

    fn ctx(port: u16) -> GuardContext {
        let addr: SocketAddr = format!("1.2.3.4:{}", port).parse().unwrap();
        GuardContext::new(addr, None, false)
    }

    #[test]
    fn half_open_counter_released_on_close_without_establish() {
        let guard = SynGuard::new(SynGuardConfig { max_half_open_global: 2, ..Default::default() });

        // Reserve two connections — fills the global limit.
        guard.on_reserve(&ctx(1001)).expect("reserve 1");
        guard.on_reserve(&ctx(1002)).expect("reserve 2");

        // Third should be rejected.
        assert!(guard.on_reserve(&ctx(1003)).is_err(), "should be at limit");

        // Close the first without establishing — simulates a TLS handshake failure.
        guard.on_close(&ctx(1001));

        // Now there is room for one more.
        guard.on_reserve(&ctx(1004)).expect("room after close");
    }

    #[test]
    fn half_open_counter_not_double_decremented_after_establish() {
        let guard = SynGuard::new(SynGuardConfig { max_half_open_global: 1, ..Default::default() });
        guard.on_reserve(&ctx(1001)).expect("reserve");
        guard.on_established(&ctx(1001)).expect("establish");
        // Close after establish — must NOT double-decrement (would underflow).
        guard.on_close(&ctx(1001));

        // The global counter should now be 0, allowing another connection.
        guard.on_reserve(&ctx(1002)).expect("slot free after established close");
    }
}
