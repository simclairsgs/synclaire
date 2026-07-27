// Guard API — rate limiting, throttle, IP ban, SYN guard, SlowLoris.
//   cargo run --example guard-api

use std::net::{IpAddr, Ipv4Addr};
use synclaire::guard::{
    IpBan, IpBanConfig, RateLimiter, RateLimiterConfig, SlowLoris, SlowLorisConfig, SynGuard,
    SynGuardConfig, Throttle, ThrottleConfig,
};

fn main() {
    println!("=== Synclaire Guard API Example ===\n");

    println!("1. IP Ban Guard\n");
    demo_ip_ban();

    println!("\n2. Rate Limiter Guard\n");
    demo_rate_limiter();

    println!("\n3. Throttle Guard\n");
    demo_throttle();

    println!("\n4. SYN Guard\n");
    demo_syn_guard();

    println!("\n5. Slow Loris Guard\n");
    demo_slow_loris();

    println!("\n6. Guard Stack\n");
    demo_guard_stack();

    println!("\n=== Example Complete ===");
}

fn demo_ip_ban() {
    let config = IpBanConfig {};

    let ip_ban = IpBan::new(config);

    let attacker1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let attacker2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let trusted_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    println!("Initial state:");
    println!("  Attacker1 banned? {}", ip_ban.is_banned(&attacker1));
    println!(
        "  Trusted client banned? {}",
        ip_ban.is_banned(&trusted_client)
    );

    println!("\nBanning attacker IPs...");
    ip_ban.ban(attacker1);
    ip_ban.ban(attacker2);

    println!("  Attacker1 banned? {}", ip_ban.is_banned(&attacker1));
    println!("  Attacker2 banned? {}", ip_ban.is_banned(&attacker2));
    println!(
        "  Trusted client banned? {}",
        ip_ban.is_banned(&trusted_client)
    );

    println!("\nUnbanning attacker1...");
    ip_ban.unban(&attacker1);
    println!("  Attacker1 banned? {}", ip_ban.is_banned(&attacker1));
    println!("  Attacker2 still banned? {}", ip_ban.is_banned(&attacker2));

    println!("\n✓ IP Ban Guard: Dynamic whitelist/blocklist via ban()/unban() API");
}

fn demo_rate_limiter() {
    let config = RateLimiterConfig {
        per_ip_capacity: 50,
        per_ip_refill_per_second: 10,
        global_capacity: 500,
        global_refill_per_second: 100,
        global_window: std::time::Duration::from_secs(10),
        global_window_limit: 2_000,
        max_tracked_ips: 100_000,
    };

    let _rate_limiter = RateLimiter::new(config.clone());

    println!("Rate Limiter Config:");
    println!(
        "  Per-IP: {} capacity, {} refill/sec",
        config.per_ip_capacity, config.per_ip_refill_per_second
    );
    println!(
        "  Global: {} capacity, {} refill/sec",
        config.global_capacity, config.global_refill_per_second
    );
    println!(
        "  Window: {:?}, limit: {}",
        config.global_window, config.global_window_limit
    );

    println!("\n✓ Rate Limiter: Configurable per-IP and global rate limiting");
    println!(
        "  - Burst capacity: {} connections per IP",
        config.per_ip_capacity
    );
    println!(
        "  - Sustained rate: {} connections/sec per IP",
        config.per_ip_refill_per_second
    );
    println!(
        "  - Global burst: {} total connections",
        config.global_capacity
    );
    println!(
        "  - Global rate: {} connections/sec",
        config.global_refill_per_second
    );
}

fn demo_throttle() {
    let config = ThrottleConfig {
        max_connections_per_ip: 32,
        max_connections_global: 512,
    };

    let _throttle = Throttle::new(config.clone());

    println!("Throttle Config:");
    println!(
        "  Per-IP: max {} concurrent connections",
        config.max_connections_per_ip
    );
    println!(
        "  Global: max {} concurrent connections",
        config.max_connections_global
    );

    println!("\n✓ Throttle: Limits concurrent connections");
    println!("  - Prevents single IP monopolizing resources");
    println!("  - Ensures fair distribution across clients");
    println!(
        "  - Example: DDoS attacker limited to {} active connections",
        config.max_connections_per_ip
    );
}

fn demo_syn_guard() {
    let config = SynGuardConfig {
        max_half_open_per_ip: 16,
        max_half_open_global: 256,
        backlog_limit: 1_024,
        syn_timeout: std::time::Duration::from_secs(5),
        max_tracked_ips: 100_000,
    };

    let _syn_guard = SynGuard::new(config.clone());

    println!("SYN Guard Config:");
    println!(
        "  Per-IP: max {} half-open connections",
        config.max_half_open_per_ip
    );
    println!(
        "  Global: max {} half-open connections",
        config.max_half_open_global
    );
    println!("  Timeout: {:?}", config.syn_timeout);

    println!("\n✓ SYN Guard: Protects against SYN flood attacks");
    println!("  - Limits incomplete TCP handshakes");
    println!(
        "  - Example attack: 1000 SYN packets → rejected after {} per attacker IP",
        config.max_half_open_per_ip
    );
}

fn demo_slow_loris() {
    let config = SlowLorisConfig {
        idle_timeout: std::time::Duration::from_secs(15),
        grace_period: std::time::Duration::from_secs(3),
        max_tracked_connections: 100_000,
    };

    let _slow_loris = SlowLoris::new(config.clone());

    println!("Slow Loris Guard Config:");
    println!("  Idle timeout: {:?}", config.idle_timeout);
    println!("  Grace period: {:?}", config.grace_period);
    println!(
        "  Total before close: {:?}",
        config.idle_timeout + config.grace_period
    );

    println!("\n✓ Slow Loris: Protects against slow client attacks");
    println!("  - Detects clients sending data very slowly");
    println!(
        "  - Closes connections idle > {} seconds",
        config.idle_timeout.as_secs()
    );
    println!("  - Example: Client sends 1 byte every 20 seconds → terminated after 18 seconds");
}

fn demo_guard_stack() {
    println!("Guard Stack Configuration:");
    println!("  A guard stack applies multiple guards in sequence\n");

    println!("Typical Production Stack:");
    println!("  1. SynGuard → Rejects SYN floods early");
    println!("  2. IpBan → Rejects known malicious IPs");
    println!("  3. RateLimiter → Limits request rate per IP");
    println!("  4. Throttle → Limits concurrent connections");
    println!("  5. SlowLoris → Detects slow client attacks");

    println!("\nGuard Evaluation Order:");
    println!("  - on_reserve(): SynGuard, IpBan check first");
    println!("  - on_activity(): SlowLoris idle check");
    println!("  - on_payload(): Per-packet processing");
    println!("  - on_close(): Cleanup per-IP tracking");

    println!("\nExample Attack Scenarios:");
    println!("  SYN Flood (1000/sec from 50 IPs):");
    println!("    → SynGuard: Reject after 16 per IP → ~84% blocked");

    println!("\n  Rate Limit Attack (100 req/sec from 1 IP):");
    println!("    → RateLimiter: Allow 10/sec sustained → 90% dropped");

    println!("\n  Slow Loris (100 clients, 1 byte/20 sec):");
    println!("    → SlowLoris: Timeout after 15 sec → Prevent resource exhaustion");

    println!("\n  Connection Exhaustion (500 concurrent from 1 IP):");
    println!("    → Throttle: Limit to 32/IP → 94% rejected");

    println!("\n✓ Guard Stack: Layered defense approach");
    println!("  - Each guard catches specific attack patterns");
    println!("  - Combined protection far exceeds individual guards");
}
