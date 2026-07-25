use std::{
    collections::HashMap,
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

use parking_lot::Mutex;

use crate::{guard::{Guard, GuardContext}, SynError};

#[derive(Clone, Debug)]
pub struct ThrottleConfig {
    pub max_connections_per_ip: usize,
    pub max_connections_global: usize,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: 1_000,
            max_connections_global: 100_000,
        }
    }
}

pub struct Throttle {
    config: ThrottleConfig,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    global: AtomicUsize,
}

impl Throttle {
    pub fn new(config: ThrottleConfig) -> Self {
        Self {
            config,
            per_ip: Mutex::new(HashMap::new()),
            global: AtomicUsize::new(0),
        }
    }

    fn acquire(&self, ip: IpAddr) -> Result<(), SynError> {
        let current_global = self.global.fetch_add(1, Ordering::SeqCst) + 1;
        if current_global > self.config.max_connections_global {
            self.global.fetch_sub(1, Ordering::SeqCst);
            return Err(SynError::throttled("global", self.config.max_connections_global));
        }

        let mut per_ip = self.per_ip.lock();
        let current_ip = per_ip.entry(ip).or_insert(0);
        *current_ip += 1;

        if *current_ip > self.config.max_connections_per_ip {
            *current_ip -= 1;
            self.global.fetch_sub(1, Ordering::SeqCst);
            return Err(SynError::throttled("per-ip", self.config.max_connections_per_ip));
        }

        Ok(())
    }

    fn release(&self, ip: IpAddr) {
        self.global.fetch_sub(1, Ordering::SeqCst);
        let mut per_ip = self.per_ip.lock();
        if let Some(count) = per_ip.get_mut(&ip) {
            if *count > 1 {
                *count -= 1;
            } else {
                per_ip.remove(&ip);
            }
        }
    }
}

impl Guard for Throttle {
    fn name(&self) -> &'static str {
        "throttle"
    }

    fn on_reserve(&self, context: &GuardContext) -> Result<(), SynError> {
        self.acquire(context.peer_ip)
    }

    fn on_close(&self, context: &GuardContext) {
        self.release(context.peer_ip);
    }
}