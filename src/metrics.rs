use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct ConnectionMetrics {
    pub tcp_connections_total: u64,
    pub tls_connections_total: u64,
    pub mtls_connections_total: u64,
    pub failed_connections: u64,
    pub active_connections: u64,
    pub avg_latency_ms: f64,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub per_server: HashMap<String, ServerMetrics>,
    pub per_ip: HashMap<IpAddr, IpMetrics>,
}

#[derive(Clone, Debug)]
pub struct ServerMetrics {
    pub tcp: u64,
    pub tls: u64,
    pub mtls: u64,
    pub active: u64,
    pub failures: u64,
    pub avg_latency_ms: f64,
    pub latency_sample_count: u64, // For latency calculation
}

#[derive(Clone, Debug)]
pub struct IpMetrics {
    pub connections: u64,
    pub active: u64,
    pub failures: u64,
    pub avg_latency_ms: f64,
}

pub trait MetricsCallback: Send + Sync {
    fn on_metrics(&self, metrics: &ConnectionMetrics);
}

pub struct MetricsCollector {
    tcp_total: Arc<AtomicU64>,
    tls_total: Arc<AtomicU64>,
    mtls_total: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
    active: Arc<AtomicU64>,
    latency_sum_ms: Arc<AtomicU64>,  // Total latency sum in ms
    latency_count: Arc<AtomicU64>,   // Count of latency measurements
    min_latency_ms: Arc<Mutex<u64>>, // Minimum observed latency
    max_latency_ms: Arc<Mutex<u64>>, // Maximum observed latency
    per_server: Arc<Mutex<HashMap<String, PerServerMetrics>>>,
    per_ip: Arc<Mutex<HashMap<IpAddr, PerIpMetrics>>>,
    callbacks: Arc<Mutex<Vec<Arc<dyn MetricsCallback>>>>,
}

#[derive(Clone, Debug)]
struct PerServerMetrics {
    tcp: u64,
    tls: u64,
    mtls: u64,
    active: u64,
    failures: u64,
    latency_sum_ms: u64,
    latency_count: u64,
}

#[derive(Clone, Debug)]
struct PerIpMetrics {
    connections: u64,
    active: u64,
    failures: u64,
    latency_sum_ms: u64,
    latency_count: u64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            tcp_total: Arc::new(AtomicU64::new(0)),
            tls_total: Arc::new(AtomicU64::new(0)),
            mtls_total: Arc::new(AtomicU64::new(0)),
            failed: Arc::new(AtomicU64::new(0)),
            active: Arc::new(AtomicU64::new(0)),
            latency_sum_ms: Arc::new(AtomicU64::new(0)),
            latency_count: Arc::new(AtomicU64::new(0)),
            min_latency_ms: Arc::new(Mutex::new(u64::MAX)),
            max_latency_ms: Arc::new(Mutex::new(0)),
            per_server: Arc::new(Mutex::new(HashMap::new())),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            callbacks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn record_tcp_connection(&self, server_name: Option<&str>, peer_ip: IpAddr) {
        self.tcp_total.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);

        if let Some(name) = server_name {
            let mut per_server = self.per_server.lock();
            if let Some(m) = per_server.get_mut(name) {
                m.tcp += 1;
                m.active += 1;
            } else {
                per_server.insert(
                    name.to_string(),
                    PerServerMetrics {
                        tcp: 1,
                        tls: 0,
                        mtls: 0,
                        active: 1,
                        failures: 0,
                        latency_sum_ms: 0,
                        latency_count: 0,
                    },
                );
            }
        }

        let mut per_ip = self.per_ip.lock();
        per_ip
            .entry(peer_ip)
            .and_modify(|m| {
                m.connections += 1;
                m.active += 1;
            })
            .or_insert(PerIpMetrics {
                connections: 1,
                active: 1,
                failures: 0,
                latency_sum_ms: 0,
                latency_count: 0,
            });
    }

    pub fn record_tls_connection(&self, server_name: Option<&str>, peer_ip: IpAddr) {
        self.tls_total.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);

        if let Some(name) = server_name {
            let mut per_server = self.per_server.lock();
            if let Some(m) = per_server.get_mut(name) {
                m.tls += 1;
                m.active += 1;
            } else {
                per_server.insert(
                    name.to_string(),
                    PerServerMetrics {
                        tcp: 0,
                        tls: 1,
                        mtls: 0,
                        active: 1,
                        failures: 0,
                        latency_sum_ms: 0,
                        latency_count: 0,
                    },
                );
            }
        }

        let mut per_ip = self.per_ip.lock();
        per_ip
            .entry(peer_ip)
            .and_modify(|m| {
                m.connections += 1;
                m.active += 1;
            })
            .or_insert(PerIpMetrics {
                connections: 1,
                active: 1,
                failures: 0,
                latency_sum_ms: 0,
                latency_count: 0,
            });
    }

    pub fn record_mtls_connection(&self, server_name: Option<&str>, peer_ip: IpAddr) {
        self.mtls_total.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);

        if let Some(name) = server_name {
            let mut per_server = self.per_server.lock();
            if let Some(m) = per_server.get_mut(name) {
                m.mtls += 1;
                m.active += 1;
            } else {
                per_server.insert(
                    name.to_string(),
                    PerServerMetrics {
                        tcp: 0,
                        tls: 0,
                        mtls: 1,
                        active: 1,
                        failures: 0,
                        latency_sum_ms: 0,
                        latency_count: 0,
                    },
                );
            }
        }

        let mut per_ip = self.per_ip.lock();
        per_ip
            .entry(peer_ip)
            .and_modify(|m| {
                m.connections += 1;
                m.active += 1;
            })
            .or_insert(PerIpMetrics {
                connections: 1,
                active: 1,
                failures: 0,
                latency_sum_ms: 0,
                latency_count: 0,
            });
    }

    pub fn record_failure(&self, server_name: Option<&str>, peer_ip: IpAddr) {
        self.failed.fetch_add(1, Ordering::Relaxed);

        if let Some(name) = server_name {
            let mut per_server = self.per_server.lock();
            if let Some(m) = per_server.get_mut(name) {
                m.failures += 1;
            } else {
                per_server.insert(
                    name.to_string(),
                    PerServerMetrics {
                        tcp: 0,
                        tls: 0,
                        mtls: 0,
                        active: 0,
                        failures: 1,
                        latency_sum_ms: 0,
                        latency_count: 0,
                    },
                );
            }
        }

        let mut per_ip = self.per_ip.lock();
        per_ip
            .entry(peer_ip)
            .and_modify(|m| m.failures += 1)
            .or_insert(PerIpMetrics {
                connections: 0,
                active: 0,
                failures: 1,
                latency_sum_ms: 0,
                latency_count: 0,
            });
    }

    pub fn record_connection_close(&self, server_name: Option<&str>, peer_ip: IpAddr) {
        // Saturate at 0 to prevent wrapping on double-close.
        self.active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            })
            .ok();

        if let Some(name) = server_name {
            let mut per_server = self.per_server.lock();
            if let Some(m) = per_server.get_mut(name) {
                if m.active > 0 {
                    m.active -= 1;
                }
            }
        }

        let mut per_ip = self.per_ip.lock();
        if let Some(m) = per_ip.get_mut(&peer_ip) {
            if m.active > 0 {
                m.active -= 1;
            }
        }
    }

    pub fn record_connection_latency(
        &self,
        server_name: Option<&str>,
        peer_ip: IpAddr,
        latency_ms: u64,
    ) {
        // Update global latency metrics
        self.latency_sum_ms.fetch_add(latency_ms, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);

        // Update min/max global latency
        {
            let mut min = self.min_latency_ms.lock();
            if latency_ms < *min {
                *min = latency_ms;
            }
        }
        {
            let mut max = self.max_latency_ms.lock();
            if latency_ms > *max {
                *max = latency_ms;
            }
        }

        // Update per-server latency
        if let Some(name) = server_name {
            let mut per_server = self.per_server.lock();
            if let Some(m) = per_server.get_mut(name) {
                m.latency_sum_ms += latency_ms;
                m.latency_count += 1;
            }
        }

        // Update per-IP latency
        {
            let mut per_ip = self.per_ip.lock();
            if let Some(m) = per_ip.get_mut(&peer_ip) {
                m.latency_sum_ms += latency_ms;
                m.latency_count += 1;
            }
        }
    }

    pub fn register_callback(&self, callback: Arc<dyn MetricsCallback>) {
        self.callbacks.lock().push(callback);
    }

    pub fn snapshot(&self) -> ConnectionMetrics {
        let per_server = self.per_server.lock();
        let per_server_metrics = per_server
            .iter()
            .map(|(name, m)| {
                let avg_latency_ms = if m.latency_count > 0 {
                    (m.latency_sum_ms as f64) / (m.latency_count as f64)
                } else {
                    0.0
                };
                (
                    name.clone(),
                    ServerMetrics {
                        tcp: m.tcp,
                        tls: m.tls,
                        mtls: m.mtls,
                        active: m.active,
                        failures: m.failures,
                        avg_latency_ms,
                        latency_sample_count: m.latency_count,
                    },
                )
            })
            .collect();

        let per_ip = self.per_ip.lock();
        let per_ip_metrics = per_ip
            .iter()
            .map(|(ip, m)| {
                let avg_latency_ms = if m.latency_count > 0 {
                    (m.latency_sum_ms as f64) / (m.latency_count as f64)
                } else {
                    0.0
                };
                (
                    *ip,
                    IpMetrics {
                        connections: m.connections,
                        active: m.active,
                        failures: m.failures,
                        avg_latency_ms,
                    },
                )
            })
            .collect();

        let latency_count = self.latency_count.load(Ordering::Relaxed);
        let avg_latency_ms = if latency_count > 0 {
            (self.latency_sum_ms.load(Ordering::Relaxed) as f64) / (latency_count as f64)
        } else {
            0.0
        };

        let min_latency_ms = {
            let min = self.min_latency_ms.lock();
            if *min == u64::MAX {
                0
            } else {
                *min
            }
        };

        let max_latency_ms = *self.max_latency_ms.lock();

        ConnectionMetrics {
            tcp_connections_total: self.tcp_total.load(Ordering::Relaxed),
            tls_connections_total: self.tls_total.load(Ordering::Relaxed),
            mtls_connections_total: self.mtls_total.load(Ordering::Relaxed),
            failed_connections: self.failed.load(Ordering::Relaxed),
            active_connections: self.active.load(Ordering::Relaxed),
            avg_latency_ms,
            min_latency_ms,
            max_latency_ms,
            per_server: per_server_metrics,
            per_ip: per_ip_metrics,
        }
    }

    pub fn trigger_callbacks(&self) {
        let metrics = self.snapshot();
        let callbacks = self.callbacks.lock();
        for callback in callbacks.iter() {
            callback.on_metrics(&metrics);
        }
    }

    pub fn reset(&self) {
        self.tcp_total.store(0, Ordering::Relaxed);
        self.tls_total.store(0, Ordering::Relaxed);
        self.mtls_total.store(0, Ordering::Relaxed);
        self.failed.store(0, Ordering::Relaxed);
        self.active.store(0, Ordering::Relaxed);
        self.latency_sum_ms.store(0, Ordering::Relaxed);
        self.latency_count.store(0, Ordering::Relaxed);
        *self.min_latency_ms.lock() = u64::MAX;
        *self.max_latency_ms.lock() = 0;
        self.per_server.lock().clear();
        self.per_ip.lock().clear();
    }
}

impl Clone for MetricsCollector {
    fn clone(&self) -> Self {
        Self {
            tcp_total: Arc::clone(&self.tcp_total),
            tls_total: Arc::clone(&self.tls_total),
            mtls_total: Arc::clone(&self.mtls_total),
            failed: Arc::clone(&self.failed),
            active: Arc::clone(&self.active),
            latency_sum_ms: Arc::clone(&self.latency_sum_ms),
            latency_count: Arc::clone(&self.latency_count),
            min_latency_ms: Arc::clone(&self.min_latency_ms),
            max_latency_ms: Arc::clone(&self.max_latency_ms),
            per_server: Arc::clone(&self.per_server),
            per_ip: Arc::clone(&self.per_ip),
            callbacks: Arc::clone(&self.callbacks),
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LoggingMetricsCallback;

impl MetricsCallback for LoggingMetricsCallback {
    fn on_metrics(&self, metrics: &ConnectionMetrics) {
        log::info!(
            "Metrics: TCP={}, TLS={}, mTLS={}, Failed={}, Active={}",
            metrics.tcp_connections_total,
            metrics.tls_connections_total,
            metrics.mtls_connections_total,
            metrics.failed_connections,
            metrics.active_connections
        );

        for (server, server_metrics) in &metrics.per_server {
            log::debug!(
                "  Server '{}': TCP={}, TLS={}, mTLS={}, Active={}, Failures={}",
                server,
                server_metrics.tcp,
                server_metrics.tls,
                server_metrics.mtls,
                server_metrics.active,
                server_metrics.failures
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_metrics_collector_tcp() {
        let collector = MetricsCollector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        collector.record_tcp_connection(Some("test-server"), ip);
        let metrics = collector.snapshot();

        assert_eq!(metrics.tcp_connections_total, 1);
        assert_eq!(metrics.tls_connections_total, 0);
        assert_eq!(metrics.active_connections, 1);
    }

    #[test]
    fn test_metrics_collector_tls() {
        let collector = MetricsCollector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        collector.record_tls_connection(Some("tls-server"), ip);
        let metrics = collector.snapshot();

        assert_eq!(metrics.tls_connections_total, 1);
        assert_eq!(metrics.active_connections, 1);
    }

    #[test]
    fn test_metrics_collector_connection_close() {
        let collector = MetricsCollector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        collector.record_tcp_connection(Some("server"), ip);
        assert_eq!(collector.snapshot().active_connections, 1);

        collector.record_connection_close(Some("server"), ip);
        assert_eq!(collector.snapshot().active_connections, 0);
    }

    #[test]
    fn test_metrics_per_server() {
        let collector = MetricsCollector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        collector.record_tcp_connection(Some("server1"), ip);
        collector.record_tls_connection(Some("server2"), ip);
        collector.record_tcp_connection(Some("server1"), ip);

        let metrics = collector.snapshot();
        assert_eq!(metrics.per_server.len(), 2);
        assert_eq!(metrics.per_server["server1"].tcp, 2);
        assert_eq!(metrics.per_server["server2"].tls, 1);
    }

    #[test]
    fn test_metrics_callback() {
        use std::sync::atomic::AtomicBool;

        struct TestCallback {
            called: Arc<AtomicBool>,
        }

        impl MetricsCallback for TestCallback {
            fn on_metrics(&self, _metrics: &ConnectionMetrics) {
                self.called.store(true, Ordering::SeqCst);
            }
        }

        let collector = MetricsCollector::new();
        let called = Arc::new(AtomicBool::new(false));
        let callback = Arc::new(TestCallback {
            called: Arc::clone(&called),
        });

        collector.register_callback(callback);
        collector.trigger_callbacks();

        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_double_close_does_not_wrap_active_counter() {
        let collector = MetricsCollector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        collector.record_tcp_connection(Some("s"), ip);
        collector.record_connection_close(Some("s"), ip);
        // Double close — should not wrap to u64::MAX.
        collector.record_connection_close(Some("s"), ip);
        let snap = collector.snapshot();
        assert_eq!(snap.active_connections, 0, "must saturate at 0, not wrap");
    }
}
