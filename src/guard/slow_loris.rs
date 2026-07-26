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
    map: HashMap<SocketAddr, ActivityEntry>,
    order: VecDeque<(SocketAddr, u64)>,
    max: usize,
    next_seq: u64,
}

struct ActivityEntry {
    last_seen: Instant,
    seq: u64,
}

impl BoundedActivityMap {
    fn new(max: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            max: max.max(1),
            next_seq: 0,
        }
    }

    fn note(&mut self, addr: SocketAddr) {
        self.next_seq = self.next_seq.wrapping_add(1);
        let seq = self.next_seq;
        let is_new = self.map.insert(addr, ActivityEntry {
            last_seen: Instant::now(),
            seq,
        }).is_none();

        self.order.push_back((addr, seq));

        if is_new && self.map.len() > self.max {
            self.evict_oldest_live();
        }

        if self.order.len() > self.max.saturating_mul(4).max(16) {
            self.compact_order();
        }
    }

    fn evict_oldest_live(&mut self) {
        while let Some((addr, seq)) = self.order.pop_front() {
            if self.map.get(&addr).is_some_and(|entry| entry.seq == seq) {
                self.map.remove(&addr);
                break;
            }
        }
    }

    fn compact_order(&mut self) {
        let mut compacted = VecDeque::with_capacity(self.map.len());
        while let Some((addr, seq)) = self.order.pop_front() {
            if self.map.get(&addr).is_some_and(|entry| entry.seq == seq) {
                compacted.push_back((addr, seq));
            }
        }
        self.order = compacted;
    }

    fn get(&self, addr: &SocketAddr) -> Option<Instant> {
        self.map.get(addr).map(|entry| entry.last_seen)
    }

    fn remove(&mut self, addr: &SocketAddr) {
        self.map.remove(addr);
        if self.order.len() > self.max.saturating_mul(4).max(16) {
            self.compact_order();
        }
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
        self.check_idle(context.peer_addr)?;
        self.note(context.peer_addr);
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
