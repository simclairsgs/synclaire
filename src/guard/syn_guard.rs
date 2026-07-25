use std::{
    collections::HashMap,
    net::IpAddr,
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
}

impl Default for SynGuardConfig {
    fn default() -> Self {
        Self {
            max_half_open_per_ip: 32,
            max_half_open_global: 512,
            backlog_limit: 1_024,
            syn_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Default)]
struct HalfOpenState {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
    started_at: HashMap<IpAddr, Instant>,
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
        let _ = self.config.backlog_limit;

        let next_total = state.total + 1;
        let next_ip = state.per_ip.get(&ip).copied().unwrap_or(0) + 1;

        if next_total > self.config.max_half_open_global {
            return Err(SynError::throttled("half-open global", self.config.max_half_open_global));
        }

        if next_ip > self.config.max_half_open_per_ip {
            return Err(SynError::throttled("half-open per-ip", self.config.max_half_open_per_ip));
        }

        state.total = next_total;
        state.per_ip.insert(ip, next_ip);
        state.started_at.entry(ip).or_insert_with(Instant::now);

        Ok(())
    }

    fn establish(&self, ip: IpAddr) {
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
        self.establish(context.peer_ip);
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
}