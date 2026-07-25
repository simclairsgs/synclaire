use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use crate::{guard::{Guard, GuardContext}, SynError};

#[derive(Clone, Debug)]
pub struct SlowLorisConfig {
    pub idle_timeout: Duration,
    pub grace_period: Duration,
}

impl Default for SlowLorisConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(15),
            grace_period: Duration::from_secs(3),
        }
    }
}

pub struct SlowLoris {
    config: SlowLorisConfig,
    last_activity: Mutex<HashMap<IpAddr, Instant>>,
}

impl SlowLoris {
    pub fn new(config: SlowLorisConfig) -> Self {
        Self {
            config,
            last_activity: Mutex::new(HashMap::new()),
        }
    }

    fn note(&self, ip: IpAddr) {
        self.last_activity.lock().insert(ip, Instant::now());
    }

    fn check_idle(&self, ip: IpAddr) -> Result<(), SynError> {
        let last_activity = self.last_activity.lock().get(&ip).copied();
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
        self.note(context.peer_ip);
        Ok(())
    }

    fn on_activity(&self, context: &GuardContext) -> Result<(), SynError> {
        self.check_idle(context.peer_ip)?;
        Ok(())
    }

    fn on_payload(&self, context: &GuardContext, _payload: &[u8]) -> Result<(), SynError> {
        self.note(context.peer_ip);
        Ok(())
    }

    fn on_close(&self, context: &GuardContext) {
        self.last_activity.lock().remove(&context.peer_ip);
    }
}