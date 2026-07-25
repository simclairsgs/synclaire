use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use crate::{guard::{Guard, GuardContext}, SynError};

#[derive(Clone, Debug)]
pub struct SlowLorisConfig {
    pub idle_timeout: Duration,
    pub grace_period: Duration,
    /// Maximum number of distinct connections tracked for idle detection.
    pub max_tracked_connections: usize,
}

impl Default for SlowLorisConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(15),
            grace_period: Duration::from_secs(3),
            max_tracked_connections: 100_000,
        }
    }
}

struct BoundedActivityMap {
    map: HashMap<SocketAddr, Instant>,
    order: VecDeque<SocketAddr>,
    max: usize,
}

impl BoundedActivityMap {
    fn new(max: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            max: max.max(1),
        }
    }

    fn note(&mut self, addr: SocketAddr) {
        if self.map.contains_key(&addr) {
            self.map.insert(addr, Instant::now());
        } else {
            if self.map.len() >= self.max {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
            self.map.insert(addr, Instant::now());
            self.order.push_back(addr);
        }
    }

    fn get(&self, addr: &SocketAddr) -> Option<Instant> {
        self.map.get(addr).copied()
    }

    fn remove(&mut self, addr: &SocketAddr) {
        self.map.remove(addr);
        // Order queue cleanup on remove is O(n) but close is infrequent; acceptable.
        self.order.retain(|a| a != addr);
    }
}

pub struct SlowLoris {
    config: SlowLorisConfig,
    last_activity: Mutex<BoundedActivityMap>,
}

impl SlowLoris {
    pub fn new(config: SlowLorisConfig) -> Self {
        let max = config.max_tracked_connections;
        Self {
            config,
            last_activity: Mutex::new(BoundedActivityMap::new(max)),
        }
    }

    fn note(&self, addr: SocketAddr) {
        self.last_activity.lock().note(addr);
    }

    fn check_idle(&self, addr: SocketAddr) -> Result<(), SynError> {
        let last_activity = self.last_activity.lock().get(&addr);
        if let Some(last_activity) = last_activity {
            let idle = last_activity.elapsed();
            if idle > self.config.idle_timeout + self.config.grace_period {
                return Err(SynError::timeout(self.config.idle_timeout, "reading from a very slow client"));
            }
        }
        Ok(())
    }
}

impl Guard for SlowLoris {
    fn name(&self) -> &'static str {
        "slow_loris"
    }

    fn on_reserve(&self, context: &GuardContext) -> Result<(), SynError> {
        self.note(context.peer_addr);
        Ok(())
    }

    fn on_activity(&self, context: &GuardContext) -> Result<(), SynError> {
        self.note(context.peer_addr);
        self.check_idle(context.peer_addr)?;
        Ok(())
    }

    fn on_payload(&self, context: &GuardContext, _payload: &[u8]) -> Result<(), SynError> {
        self.note(context.peer_addr);
        Ok(())
    }

    fn on_close(&self, context: &GuardContext) {
        self.last_activity.lock().remove(&context.peer_addr);
    }
}
