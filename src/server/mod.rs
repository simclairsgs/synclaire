#[cfg(feature = "async")]
pub mod async_server;
#[cfg(feature = "sync")]
pub mod sync_server;
pub mod tcp;
pub mod tls;

use crate::{
    config::GuardStackConfig,
    guard::{GuardStack, IpBan, RateLimiter, SlowLoris, SynGuard, Throttle, UdpAmplificationGuard},
};

pub fn build_guard_stack(config: &GuardStackConfig) -> GuardStack {
    let mut builder = GuardStack::builder();

    if let Some(rate_limiter) = &config.rate_limiter {
        builder = builder.push(RateLimiter::new(rate_limiter.clone()));
    }

    if let Some(ip_ban) = &config.ip_ban {
        builder = builder.push(IpBan::new(ip_ban.clone()));
    }

    if let Some(throttle) = &config.throttle {
        builder = builder.push(Throttle::new(throttle.clone()));
    }

    if let Some(syn_guard) = &config.syn_guard {
        builder = builder.push(SynGuard::new(syn_guard.clone()));
    }

    if let Some(slow_loris) = &config.slow_loris {
        builder = builder.push(SlowLoris::new(slow_loris.clone()));
    }

    if let Some(udp_amplification) = &config.udp_amplification {
        builder = builder.push(UdpAmplificationGuard::new(udp_amplification.clone()));
    }

    builder.build()
}