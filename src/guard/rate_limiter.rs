use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use crate::{guard::{Guard, GuardContext}, SynError};

#[derive(Clone, Debug)]
pub struct RateLimiterConfig {
    pub per_ip_capacity: u32,
    pub per_ip_refill_per_second: u32,
    pub global_capacity: u32,
    pub global_refill_per_second: u32,
    pub global_window: Duration,
    pub global_window_limit: usize,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            per_ip_capacity: 100,
            per_ip_refill_per_second: 20,
            global_capacity: 1_000,
            global_refill_per_second: 200,
            global_window: Duration::from_secs(10),
            global_window_limit: 5_000,
        }
    }
}

#[derive(Clone, Debug)]
struct TokenBucket {
    capacity: u32,
    refill_per_second: u32,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_per_second: u32) -> Self {
        Self {
            capacity,
            refill_per_second,
            tokens: capacity as f64,
            last_refill: Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        self.tokens = (self.tokens + elapsed * self.refill_per_second as f64).min(self.capacity as f64);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiter {
    config: RateLimiterConfig,
    per_ip: Mutex<HashMap<IpAddr, TokenBucket>>,
    global_bucket: Mutex<TokenBucket>,
    global_window: Mutex<VecDeque<Instant>>,
}

impl RateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            global_bucket: Mutex::new(TokenBucket::new(config.global_capacity, config.global_refill_per_second)),
            per_ip: Mutex::new(HashMap::new()),
            global_window: Mutex::new(VecDeque::new()),
            config,
        }
    }

    fn allow_global_window(&self) -> bool {
        let mut window = self.global_window.lock();
        let now = Instant::now();
        while let Some(front) = window.front() {
            if now.duration_since(*front) > self.config.global_window {
                window.pop_front();
            } else {
                break;
            }
        }

        if window.len() >= self.config.global_window_limit {
            return false;
        }

        window.push_back(now);
        true
    }

    pub fn allow(&self, ip: IpAddr) -> Result<(), SynError> {
        if !self.allow_global_window() {
            return Err(SynError::rate_limited("global sliding window", ip.to_string()));
        }

        let mut bucket = self.global_bucket.lock();
        if !bucket.allow() {
            return Err(SynError::rate_limited("global token bucket", ip.to_string()));
        }

        let mut per_ip = self.per_ip.lock();
        let entry = per_ip
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(self.config.per_ip_capacity, self.config.per_ip_refill_per_second));

        if entry.allow() {
            Ok(())
        } else {
            Err(SynError::rate_limited("per-ip token bucket", ip.to_string()))
        }
    }
}

impl Guard for RateLimiter {
    fn name(&self) -> &'static str {
        "rate_limiter"
    }

    fn on_reserve(&self, context: &GuardContext) -> Result<(), SynError> {
        self.allow(context.peer_ip)
    }
}