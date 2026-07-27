use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum StickyKey {
    #[default]
    Ip,
    IpPort,
}

#[derive(Clone, Debug)]
pub enum LoadBalancerStrategy {
    RoundRobin,
    ConsistentHash { replicas: u32, sticky: StickyKey },
}

#[derive(Clone, Debug)]
pub struct Backend {
    pub addr: SocketAddr,
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
const FNV_PRIME: u64 = 1_099_511_628_211;

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
    ring: Vec<RingNode>, // sorted by hash, used only for ConsistentHash
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

#[derive(Clone, Debug)]
pub struct BackendPool {
    inner: Arc<RwLock<PoolInner>>,
    rr_counter: Arc<AtomicUsize>,
}

impl BackendPool {
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

    pub fn consistent_hash(
        backends: impl IntoIterator<Item = impl Into<Backend>>,
        replicas: u32,
        sticky: StickyKey,
    ) -> Self {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut inner = PoolInner {
            backends: backends.into_iter().map(Into::into).collect(),
            strategy: LoadBalancerStrategy::ConsistentHash { replicas, sticky },
            ring: Vec::new(),
        };
        inner.rebuild_ring();
        Self {
            inner: Arc::new(RwLock::new(inner)),
            rr_counter: counter,
        }
    }

    pub fn add_backend(&self, backend: impl Into<Backend>) {
        let mut inner = self.inner.write();
        inner.backends.push(backend.into());
        inner.rebuild_ring();
    }

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

    pub fn backends(&self) -> Vec<SocketAddr> {
        self.inner.read().backends.iter().map(|b| b.addr).collect()
    }

    pub fn len(&self) -> usize {
        self.inner.read().backends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
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
                    StickyKey::Ip => hash_addr_ip(peer),
                    StickyKey::IpPort => hash_addr_ipport(peer),
                };
                // Binary search for first ring node with hash >= key_hash.
                let idx = inner.ring.partition_point(|node| node.hash < key_hash);
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
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
    }

    fn peer(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), 12345)
    }

    #[test]
    fn round_robin_cycles_all_backends() {
        let pool = BackendPool::round_robin([addr(8001), addr(8002), addr(8003)]);
        let peers: Vec<_> = (0..9)
            .map(|_| pool.select(peer(1, 1, 1, 1)).unwrap())
            .collect();
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
        let pool =
            BackendPool::consistent_hash([addr(8001), addr(8002), addr(8003)], 150, StickyKey::Ip);
        let p = peer(192, 168, 1, 100);
        let first = pool.select(p).unwrap();
        for _ in 0..20 {
            assert_eq!(
                pool.select(p).unwrap(),
                first,
                "same IP must always land on same backend"
            );
        }
    }

    #[test]
    fn consistent_hash_different_ips_distribute() {
        let pool =
            BackendPool::consistent_hash([addr(8001), addr(8002), addr(8003)], 150, StickyKey::Ip);
        let mut counts: HashMap<SocketAddr, usize> = HashMap::new();
        for i in 0u8..=255 {
            let p = peer(10, 0, 0, i);
            *counts.entry(pool.select(p).unwrap()).or_insert(0) += 1;
        }
        // Distribution may be uneven for a small contiguous key set, but it should not
        // collapse to a single backend.
        assert!(
            counts.len() >= 2,
            "traffic should be distributed across multiple backends"
        );
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
        assert_ne!(
            hash_a, hash_b,
            "ip+port hashes must differ for different ports"
        );
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
