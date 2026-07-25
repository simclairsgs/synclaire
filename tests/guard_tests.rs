use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use synclaire::guard::{
    event_detail, Guard, GuardContext, GuardEvent, GuardEventKind, GuardStack, IpBan, IpBanConfig,
    RateLimiter, RateLimiterConfig, SlowLoris, SlowLorisConfig, SynGuard, SynGuardConfig,
    Throttle, ThrottleConfig, UdpAmplificationConfig, UdpAmplificationGuard,
};

fn context(ip_port: &str) -> GuardContext {
    let peer_addr: SocketAddr = ip_port.parse().expect("valid socket address");
    GuardContext::new(peer_addr, None, false)
}

#[test]
fn rate_limiter_blocks_after_budget_is_spent() {
    let limiter = RateLimiter::new(RateLimiterConfig {
        per_ip_capacity: 1,
        per_ip_refill_per_second: 0,
        global_capacity: 10,
        global_refill_per_second: 0,
        global_window: Duration::from_secs(60),
        global_window_limit: 100,
    });

    let ctx = context("127.0.0.1:4000");
    assert!(Guard::on_reserve(&limiter, &ctx).is_ok());
    assert!(Guard::on_reserve(&limiter, &ctx).is_err());
}

#[test]
fn ip_ban_supports_manual_blocking() {
    let ban = IpBan::new(IpBanConfig {});

    let local_ip = "127.0.0.1".parse().expect("valid ip");
    assert!(!ban.is_banned(&local_ip));

    ban.ban(local_ip);
    assert!(ban.is_banned(&local_ip));

    ban.unban(&local_ip);
    assert!(!ban.is_banned(&local_ip));
}

#[test]
fn throttle_enforces_per_ip_limit_and_releases_on_close() {
    let throttle = Throttle::new(ThrottleConfig {
        max_connections_per_ip: 1,
        max_connections_global: 10,
    });

    let ctx = context("127.0.0.1:4001");
    assert!(Guard::on_reserve(&throttle, &ctx).is_ok());
    assert!(Guard::on_reserve(&throttle, &ctx).is_err());

    Guard::on_close(&throttle, &ctx);
    assert!(Guard::on_reserve(&throttle, &ctx).is_ok());
}

#[test]
fn syn_guard_rejects_when_half_open_limit_is_reached() {
    let guard = SynGuard::new(SynGuardConfig {
        max_half_open_per_ip: 1,
        max_half_open_global: 10,
        backlog_limit: 10,
        syn_timeout: Duration::from_secs(1),
    });

    let ctx = context("127.0.0.1:4002");
    assert!(Guard::on_reserve(&guard, &ctx).is_ok());
    assert!(Guard::on_reserve(&guard, &ctx).is_err());
}

#[test]
fn slow_loris_times_out_after_idle_period() {
    let guard = SlowLoris::new(SlowLorisConfig {
        idle_timeout: Duration::from_millis(0),
        grace_period: Duration::from_millis(0),
    });

    let ctx = context("127.0.0.1:4003");
    Guard::on_reserve(&guard, &ctx).expect("reserve should record initial activity");
    thread::sleep(Duration::from_millis(2));
    assert!(Guard::on_activity(&guard, &ctx).is_err());
}

#[test]
fn udp_amplification_guard_rejects_malformed_probe() {
    let guard = UdpAmplificationGuard::new(UdpAmplificationConfig {
        reject_malformed_tcp_probes: true,
        minimum_probe_bytes: 4,
    });

    let ctx = context("127.0.0.1:4004");
    assert!(Guard::on_payload(&guard, &ctx, &[0]).is_err());
    assert!(Guard::on_payload(&guard, &ctx, b"PING").is_ok());
}

#[test]
fn guard_stack_emits_structured_events() {
    let events: Arc<Mutex<Vec<GuardEventKind>>> = Arc::new(Mutex::new(Vec::new()));
    let events_for_hook = Arc::clone(&events);

    let stack = GuardStack::builder()
        .push(RateLimiter::new(RateLimiterConfig::default()))
        .observer(move |event: GuardEvent| {
            events_for_hook
                .lock()
                .expect("event list lock")
                .push(event.kind);
        })
        .build();

    let session = stack.reserve(context("127.0.0.1:4005")).expect("reserve should pass");
    session.mark_established().expect("establish should pass");
    session.record_payload(b"hello").expect("payload should pass");
    session.touch().expect("activity should pass");
    session.close();

    let events = events.lock().expect("event list lock");
    assert!(events.iter().any(|kind| matches!(kind, GuardEventKind::Reserve)));
    assert!(events.iter().any(|kind| matches!(kind, GuardEventKind::Established)));
    assert!(events.iter().any(|kind| matches!(kind, GuardEventKind::Payload)));
    assert!(events.iter().any(|kind| matches!(kind, GuardEventKind::Activity)));
    assert!(events.iter().any(|kind| matches!(kind, GuardEventKind::Close)));
}

#[test]
fn event_detail_formats_human_readable_timing() {
    let detail = event_detail(Duration::from_secs(2), "heartbeat");
    assert!(detail.contains("heartbeat"));
    assert!(detail.contains("2s"));
}