// Load balancer module.
//
// Provides BackendPool: a thread-safe pool of backend SocketAddrs that
// selects one per connection using either:
//
// - RoundRobin: strict cyclic rotation with an atomic counter.
// - ConsistentHash: weighted ring based on FNV-1a hashing for sticky routing.
//   The ring key can be the client IP only (IP-sticky) or IP+port (per-flow-sticky).
//
// No external crates are required.  The consistent-hash ring is a sorted Vec of
// (u64 hash, backend_index) pairs built once at construction and rebuilt on pool
// modification.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;

/// How the ring key is derived from the client address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum StickyKey {
    /// Hash on client IP address only (all ports from same IP land on same backend).
    #[default]
    Ip,
    /// Hash on client IP + port (each flow from the same IP can land on different backends).
    IpPort,
}

/// Load-balancing strategy used by `BackendPool`.
#[derive(Clone, Debug)]
pub enum LoadBalancerStrategy {
    /// Cyclic round-robin across all healthy backends.
    RoundRobin,
    /// Weighted consistent hashing for sticky routing.
    ConsistentHash {
        /// Number of virtual nodes per backend in the ring (higher = better distribution).
        replicas: u32,
        /// Which part of the client address to hash.
        sticky: StickyKey,
    },
}

/// A single backend with an optional weight.
#[derive(Clone, Debug)]
pub struct Backend {
    pub addr: SocketAddr,
    /// Relative weight used only by `ConsistentHash` (how many virtual nodes).
    /// Defaults to 1.
    pub weight: u32,
}

impl Backend {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr, weight: 1 }
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight.max(1);
        self
    }
}

impl From<SocketAddr> for Backend {
    fn from(addr: SocketAddr) -> Self {
        Self::new(addr)
    }
}

// ─── FNV-1a hash ─────────────────────────────────────────────────────────────
const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
const FNV_PRIME:  u64 = 1_099_511_628_211;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

fn hash_addr_ip(addr: SocketAddr) -> u64 {
    let key = format!("ip:{}", addr.ip());
    fnv1a(key.as_bytes())
}

fn hash_addr_ipport(addr: SocketAddr) -> u64 {
    let key = format!("ipport:{}", addr);
    fnv1a(key.as_bytes())
}

// ─── Ring node ───────────────────────────────────────────────────────────────
#[derive(Clone, Debug)]
struct RingNode {
    hash: u64,
    backend_idx: usize,
}

// ─── BackendPool ─────────────────────────────────────────────────────────────

#[derive(Debug)]
struct PoolInner {
    backends: Vec<Backend>,
    strategy: LoadBalancerStrategy,
    ring: Vec<RingNode>,          // sorted by hash, used only for ConsistentHash
}

impl PoolInner {
    fn rebuild_ring(&mut self) {
        if let LoadBalancerStrategy::ConsistentHash { replicas, .. } = &self.strategy {
            let replicas = *replicas;
            let mut ring: Vec<RingNode> = self
                .backends
                .iter()
                .enumerate()
                .flat_map(|(idx, backend)| {
                    let virtual_nodes = replicas * backend.weight;
                    (0..virtual_nodes).map(move |i| {
                        // Build a unique key per virtual node: "addr#i"
                        let key = format!("{}#{}", backend.addr, i);
                        RingNode {
                            hash: fnv1a(key.as_bytes()),
                            backend_idx: idx,
                        }
                    })
                })
                .collect();
            ring.sort_unstable_by_key(|n| n.hash);
            self.ring = ring;
        }
    }
}

/// Thread-safe pool of backend addresses.
///
/// Clone is cheap (Arc-backed).
#[derive(Clone, Debug)]
pub struct BackendPool {
    inner: Arc<RwLock<PoolInner>>,
    rr_counter: Arc<AtomicUsize>,
}

impl BackendPool {
    /// Create a round-robin pool from a list of backends.
    pub fn round_robin(backends: impl IntoIterator<Item = impl Into<Backend>>) -> Self {
        let counter = Arc::new(AtomicUsize::new(0));
        let inner = PoolInner {
            backends: backends.into_iter().map(Into::into).collect(),
            strategy: LoadBalancerStrategy::RoundRobin,
            ring: Vec::new(),
        };
        Self {
            inner: Arc::new(RwLock::new(inner)),
            rr_counter: counter,
        }
    }

    /// Create a consistent-hash pool.
    ///
    /// `replicas` is the number of virtual nodes per backend (default 150 is a good start).
    pub fn consistent_hash(
        backends: impl IntoIterator<Item = impl Into<Backend>>,
        replicas: u32,
        sticky: StickyKey,
    ) -> Self {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut inner = PoolInner {
            backends: backends.into_iter().map(Into::into).collect(),
            strategy: LoadBalancerStrategy::ConsistentHash {
                replicas,
                sticky,
            },
            ring: Vec::new(),
        };
        inner.rebuild_ring();
        Self {
            inner: Arc::new(RwLock::new(inner)),
            rr_counter: counter,
        }
    }

    /// Add a backend to the pool.
    pub fn add_backend(&self, backend: impl Into<Backend>) {
        let mut inner = self.inner.write();
        inner.backends.push(backend.into());
        inner.rebuild_ring();
    }

    /// Remove a backend by address.  Returns `true` if it was found and removed.
    pub fn remove_backend(&self, addr: &SocketAddr) -> bool {
        let mut inner = self.inner.write();
        let before = inner.backends.len();
        inner.backends.retain(|b| &b.addr != addr);
        let removed = inner.backends.len() < before;
        if removed {
            inner.rebuild_ring();
        }
        removed
    }

    /// List all current backend addresses.
    pub fn backends(&self) -> Vec<SocketAddr> {
        self.inner.read().backends.iter().map(|b| b.addr).collect()
    }

    /// Number of backends in the pool.
    pub fn len(&self) -> usize {
        self.inner.read().backends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Select a backend for the given peer address.
    ///
    /// Returns `None` if the pool is empty.
    pub fn select(&self, peer: SocketAddr) -> Option<SocketAddr> {
        let inner = self.inner.read();
        if inner.backends.is_empty() {
            return None;
        }

        match &inner.strategy {
            LoadBalancerStrategy::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % inner.backends.len();
                Some(inner.backends[idx].addr)
            }
            LoadBalancerStrategy::ConsistentHash { sticky, .. } => {
                if inner.ring.is_empty() {
                    return Some(inner.backends[0].addr);
                }
                let key_hash = match sticky {
                    StickyKey::Ip     => hash_addr_ip(peer),
                    StickyKey::IpPort => hash_addr_ipport(peer),
                };
                // Binary search for first ring node with hash >= key_hash.
                let idx = inner
                    .ring
                    .partition_point(|node| node.hash < key_hash);
                // Wrap around if we're past the end of the ring.
                let node = &inner.ring[idx % inner.ring.len()];
                Some(inner.backends[node.backend_idx].addr)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::collections::HashMap;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
    }

    fn peer(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), 12345)
    }

    #[test]
    fn round_robin_cycles_all_backends() {
        let pool = BackendPool::round_robin([addr(8001), addr(8002), addr(8003)]);
        let peers: Vec<_> = (0..9).map(|_| pool.select(peer(1, 1, 1, 1)).unwrap()).collect();
        // Pattern must repeat every 3.
        assert_eq!(peers[0], peers[3]);
        assert_eq!(peers[1], peers[4]);
        assert_eq!(peers[2], peers[5]);
        // All three backends must appear.
        let unique: std::collections::HashSet<_> = peers.iter().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn consistent_hash_same_ip_sticks() {
        let pool = BackendPool::consistent_hash(
            [addr(8001), addr(8002), addr(8003)],
            150,
            StickyKey::Ip,
        );
        let p = peer(192, 168, 1, 100);
        let first = pool.select(p).unwrap();
        for _ in 0..20 {
            assert_eq!(pool.select(p).unwrap(), first, "same IP must always land on same backend");
        }
    }

    #[test]
    fn consistent_hash_different_ips_distribute() {
        let pool = BackendPool::consistent_hash(
            [addr(8001), addr(8002), addr(8003)],
            150,
            StickyKey::Ip,
        );
        let mut counts: HashMap<SocketAddr, usize> = HashMap::new();
        for i in 0u8..=255 {
            let p = peer(10, 0, 0, i);
            *counts.entry(pool.select(p).unwrap()).or_insert(0) += 1;
        }
        // Distribution may be uneven for a small contiguous key set, but it should not
        // collapse to a single backend.
        assert!(counts.len() >= 2, "traffic should be distributed across multiple backends");
    }

    #[test]
    fn consistent_hash_ip_vs_ipport_differ() {
        let backends = [addr(8001), addr(8002), addr(8003)];
        let pool_ip = BackendPool::consistent_hash(backends, 150, StickyKey::Ip);

        // Two peers with the same IP but different ports: ip-sticky treats them the same.
        let peer_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 10000);
        let peer_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 10001);

        assert_eq!(
            pool_ip.select(peer_a).unwrap(),
            pool_ip.select(peer_b).unwrap(),
            "ip-sticky: same IP, different ports → same backend"
        );

        // ipport-sticky might differ (not guaranteed for every pair, but with 3 backends
        // and only 1 bit difference in port we verify the hashes themselves differ).
        let hash_a = super::hash_addr_ipport(peer_a);
        let hash_b = super::hash_addr_ipport(peer_b);
        assert_ne!(hash_a, hash_b, "ip+port hashes must differ for different ports");
    }

    #[test]
    fn add_remove_backend() {
        let pool = BackendPool::round_robin([addr(8001)]);
        assert_eq!(pool.len(), 1);
        pool.add_backend(addr(8002));
        assert_eq!(pool.len(), 2);
        assert!(pool.remove_backend(&addr(8001)));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.backends(), vec![addr(8002)]);
    }
}
