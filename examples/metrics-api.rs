// Metrics API Usage Example
// Demonstrates how to track connections using the MetricsCollector API.
//
// This example shows:
// 1. Creating a metrics collector
// 2. Recording different connection types (TCP, TLS, mTLS)
// 3. Registering callbacks for periodic metrics
// 4. Querying current metrics snapshot
// 5. Tracking per-server and per-IP statistics
//
// Usage:
//   cargo run --example metrics-api --features async

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use synclaire::metrics::{MetricsCollector, MetricsCallback, ConnectionMetrics};

fn main() {
    println!("=== Synclaire Metrics API Example ===\n");

    // Create a metrics collector
    let metrics = Arc::new(MetricsCollector::new());

    // Example 1: Record various connection types
    println!("1. Recording connections...");
    let client_ip_1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let client_ip_2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101));
    let client_ip_3 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    // Server 1: API server - mixed connections
    metrics.record_tcp_connection(Some("api-server"), client_ip_1);
    metrics.record_tcp_connection(Some("api-server"), client_ip_2);
    metrics.record_tls_connection(Some("api-server"), client_ip_3);

    // Server 2: Database server - TLS only
    metrics.record_tls_connection(Some("db-server"), client_ip_1);
    metrics.record_mtls_connection(Some("db-server"), client_ip_2);

    // Record some failures
    metrics.record_failure(Some("api-server"), client_ip_1);
    metrics.record_failure(Some("db-server"), client_ip_3);

    // Example 2: Get current snapshot and inspect
    println!("2. Getting metrics snapshot...");
    let snapshot = metrics.snapshot();

    println!("\nGlobal Metrics:");
    println!("  TCP connections:  {}", snapshot.tcp_connections_total);
    println!("  TLS connections:  {}", snapshot.tls_connections_total);
    println!("  mTLS connections: {}", snapshot.mtls_connections_total);
    println!("  Failed connections: {}", snapshot.failed_connections);
    println!("  Active connections: {}", snapshot.active_connections);

    // Example 3: Per-server metrics
    println!("\nPer-Server Metrics:");
    for (server_name, server_metrics) in &snapshot.per_server {
        println!("  Server '{}' :", server_name);
        println!("    TCP: {}, TLS: {}, mTLS: {}", server_metrics.tcp, server_metrics.tls, server_metrics.mtls);
        println!("    Active: {}, Failures: {}", server_metrics.active, server_metrics.failures);
    }

    // Example 4: Per-IP metrics
    println!("\nPer-IP Metrics:");
    for (ip, ip_metrics) in &snapshot.per_ip {
        println!("  IP {} :", ip);
        println!("    Connections: {}, Active: {}, Failures: {}", 
                 ip_metrics.connections, ip_metrics.active, ip_metrics.failures);
    }

    // Example 5: Register and use callbacks
    println!("\n3. Registering metrics callback...");

    // Create a custom callback that logs metrics every report
    struct PeriodicLogger {
        name: String,
    }

    impl MetricsCallback for PeriodicLogger {
        fn on_metrics(&self, metrics: &ConnectionMetrics) {
            println!(
                "[{}] Metrics Report: TCP={}, TLS={}, mTLS={}, Active={}, Failed={}",
                self.name,
                metrics.tcp_connections_total,
                metrics.tls_connections_total,
                metrics.mtls_connections_total,
                metrics.active_connections,
                metrics.failed_connections
            );
        }
    }

    let callback = Arc::new(PeriodicLogger {
        name: "CustomLogger".to_string(),
    });
    metrics.register_callback(callback);

    // Trigger the callback
    println!("\n4. Triggering callbacks...");
    metrics.trigger_callbacks();

    // Example 6: Simulate connection lifecycle
    println!("\n5. Simulating connection lifecycle...");
    let sim_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    println!("  Opening 3 connections to 'web-server'...");
    metrics.record_tcp_connection(Some("web-server"), sim_ip);
    metrics.record_tcp_connection(Some("web-server"), sim_ip);
    metrics.record_tls_connection(Some("web-server"), sim_ip);

    let snapshot = metrics.snapshot();
    println!("  Active connections after opens: {}", snapshot.active_connections);

    println!("  Closing 1 connection...");
    metrics.record_connection_close(Some("web-server"), sim_ip);

    let snapshot = metrics.snapshot();
    println!("  Active connections after close: {}", snapshot.active_connections);
    if let Some(web_server) = snapshot.per_server.get("web-server") {
        println!("  web-server active: {}", web_server.active);
    }

    // Example 7: Real-time monitoring simulation
    println!("\n6. Simulating real-time metrics (5 events)...");
    let metrics_clone = Arc::clone(&metrics);

    std::thread::spawn(move || {
        for i in 0..5 {
            std::thread::sleep(Duration::from_millis(500));

            let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, i as u8));
            match i {
                0 => metrics_clone.record_tcp_connection(Some("monitor"), ip),
                1 => metrics_clone.record_tls_connection(Some("monitor"), ip),
                2 => metrics_clone.record_mtls_connection(Some("monitor"), ip),
                3 => metrics_clone.record_failure(Some("monitor"), ip),
                4 => metrics_clone.record_connection_close(Some("monitor"), ip),
                _ => {}
            }

            let snapshot = metrics_clone.snapshot();
            println!(
                "  Event {}: TCP={}, TLS={}, mTLS={}, Active={}, Failed={}",
                i,
                snapshot.tcp_connections_total,
                snapshot.tls_connections_total,
                snapshot.mtls_connections_total,
                snapshot.active_connections,
                snapshot.failed_connections
            );
        }
    });

    // Wait for monitoring thread
    std::thread::sleep(Duration::from_secs(3));

    // Final snapshot
    println!("\n7. Final metrics snapshot:");
    let final_snapshot = metrics.snapshot();
    println!("Total connections: TCP={}, TLS={}, mTLS={}, Failed={}",
             final_snapshot.tcp_connections_total,
             final_snapshot.tls_connections_total,
             final_snapshot.mtls_connections_total,
             final_snapshot.failed_connections);
    println!("Active: {}", final_snapshot.active_connections);

    println!("\n=== Example Complete ===");
}
