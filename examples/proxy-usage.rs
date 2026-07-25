// Proxy usage example: proxy server, proxy client, backend server.
//
// Modes:
// - backend: Synclaire SyncServer echo backend on a dynamic port
// - demo: backend + proxy run in-process; backend's actual port passed to proxy routing table
// - proxy-server <backend_port>: proxy listener on a dynamic port, routing to <backend_port>
//                                (guards + dynamic credential rotation + IP routing table)
// - proxy-server-async: tokio-based proxy with optional TLS offload
// - proxy-client <proxy_port> [payload]: client request through proxy
// - proxy-client-bad-creds <proxy_port>: demonstrates auth rejection
//
// Run order (all-in-one):
// 1) cargo run --example proxy-usage --features sync -- demo
//
// Run order (manual, three terminals):
// 1) cargo run --example proxy-usage --features sync -- backend
//    → prints "Backend (SyncServer) listening on port <N>"
// 2) cargo run --example proxy-usage --features sync -- proxy-server <N>
//    → proxy logs its actual bound port
// 3) cargo run --example proxy-usage --features sync -- proxy-client <proxy_port> "hello via proxy"

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use synclaire::{
    Backend, BackendPool, Connection, GuardStackConfig, IpGroup, IpPrefix,
    MetricsCollector, ProxyAuth, ProxyAuthHandle, ProxyClient, ProxyConfig, ProxyServer,
    RateLimiterConfig, RouteAction, RoutingRule, RoutingTable, ServerConfig, StickyKey,
    SyncServer,
};
use synclaire::SyncConnectionHandler;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("demo");

    match mode {
        "backend" => run_backend_server(),
        "demo" => run_demo(),
        "proxy-server" => {
            let backend_port = args
                .get(2)
                .and_then(|s| s.parse::<u16>().ok())
                .ok_or("proxy-server requires a <backend_port> argument: cargo run --example proxy-usage -- proxy-server <port>")?;
            run_proxy_server(backend_port)
        }
        "proxy-server-lb" => run_proxy_server_lb(),
        "proxy-server-async" => run_proxy_server_async(),
        "proxy-client" => {
            let proxy_port = args
                .get(2)
                .and_then(|s| s.parse::<u16>().ok())
                .ok_or("proxy-client requires a <proxy_port> argument: cargo run --example proxy-usage -- proxy-client <port> [payload]")?;
            run_proxy_client(proxy_port, args.get(3).cloned())
        }
        "proxy-client-bad-creds" => {
            let proxy_port = args
                .get(2)
                .and_then(|s| s.parse::<u16>().ok())
                .ok_or("proxy-client-bad-creds requires a <proxy_port> argument: cargo run --example proxy-usage -- proxy-client-bad-creds <port>")?;
            run_proxy_client_bad_credentials(proxy_port)
        }
        _ => {
            eprintln!(
                "Usage: {} [backend|demo|proxy-server <backend_port>|proxy-server-lb|proxy-server-async|proxy-client <proxy_port> [payload]|proxy-client-bad-creds <proxy_port>]",
                args[0]
            );
            Ok(())
        }
    }
}

// ───────────────────────────────────────────────────────────────
// Backend server using Synclaire SyncServer
// ───────────────────────────────────────────────────────────────

struct EchoHandler;

impl SyncConnectionHandler for EchoHandler {
    fn handle(&self, conn: Connection) -> synclaire::error::Result<()> {
        use std::io::{Read, Write};
        let peer = conn.peer_addr();
        log::info!("[backend] new connection from {}", peer);
        let mut stream = conn.into_stream().into_sync().expect("sync stream");
        let mut buf = vec![0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = stream.write_all(&buf[..n]) {
                        log::error!("[backend] write error: {}", e);
                        return Err(e.into());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut
                       || e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    log::error!("[backend] read error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }
}

fn run_backend_server() -> Result<(), Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    println!("Backend (SyncServer) listening on port {}", port);
    let config = ServerConfig::builder()
        .name("proxy-backend")
        .build();
    SyncServer::from_listener(listener, config, EchoHandler).run()?;
    Ok(())
}

// ───────────────────────────────────────────────────────────────
// Demo: backend + proxy run together in-process
// ───────────────────────────────────────────────────────────────

/// Runs backend and proxy in a single process.  The backend binds to :0 and its
/// actual port is wired directly into the proxy routing table — no hardcoded port.
fn run_demo() -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;
    use std::time::Duration;

    // ─── Backend ─────────────────────────────────────────────────────────────
    let backend_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let backend_port = backend_listener.local_addr()?.port();
    println!("Backend (SyncServer) listening on port {}", backend_port);

    let backend_config = ServerConfig::builder()
        .name("proxy-backend-demo")
        .build();
    let (shutdown, signal) = SyncServer::<EchoHandler>::shutdown_channel();
    let backend = SyncServer::from_listener(backend_listener, backend_config, EchoHandler);
    thread::spawn(move || {
        backend
            .run_until_shutdown(signal)
            .unwrap_or_else(|e| eprintln!("[demo] backend error: {}", e));
    });

    // Give the backend a moment to start accepting.
    thread::sleep(Duration::from_millis(100));

    // ─── Proxy ───────────────────────────────────────────────────────────────
    // Route loopback traffic to the backend's actual port (resolved above).
    let backend_addr: SocketAddr = format!("127.0.0.1:{}", backend_port).parse()?;
    let backend_secondary: SocketAddr = "127.0.0.1:3001".parse()?; // illustrative fallback

    let routing = Arc::new(RoutingTable::new(RouteAction::Reject));
    routing.add_group(
        "loopback",
        IpGroup::new().add_prefix(IpPrefix::v4(127, 0, 0, 0, 8)),
    );
    routing.add_rule(
        RoutingRule::new("loopback-to-backend", RouteAction::Forward(backend_addr))
            .from_group("loopback"),
    );
    routing.add_rule(
        RoutingRule::new("trusted-to-secondary", RouteAction::Forward(backend_secondary))
            .from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
    );

    let guards = GuardStackConfig {
        rate_limiter: Some(RateLimiterConfig {
            per_ip_capacity: 100,
            per_ip_refill_per_second: 50,
            global_capacity: 2000,
            global_refill_per_second: 1000,
            global_window: Duration::from_secs(10),
            global_window_limit: 5000,
            max_tracked_ips: 100_000,
        }),
        ..GuardStackConfig::default()
    };

    let metrics = Arc::new(MetricsCollector::new());
    let auth_handle = ProxyAuthHandle::new(ProxyAuth::basic("admin", "password123"));

    let listen_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let config = ProxyConfig::new(listen_addr, backend_addr)
        .with_auth(ProxyAuth::basic("admin", "password123"))
        .with_buffer_size(8192)
        .with_guards(guards)
        .with_routing(routing);

    println!(
        "Starting proxy server (routing loopback → backend port {}) …",
        backend_port
    );
    println!("Proxy will log its actual bound port. Use 'proxy-client <proxy_port>' to test.");

    let server = ProxyServer::new(config)
        .with_auth_handle(auth_handle)
        .with_metrics(metrics);
    server.run()?; // blocks; proxy logs actual bound port internally

    shutdown.shutdown();
    Ok(())
}

// ───────────────────────────────────────────────────────────────
// Proxy server with guards, routing table, dynamic auth + metrics
// ───────────────────────────────────────────────────────────────

/// Standalone proxy server.  `backend_port` must be supplied on the command line
/// (obtained from the "backend" mode printout) so that the routing table can
/// forward to the correct backend without hardcoding a port.
fn run_proxy_server(backend_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;
    use std::time::Duration;

    let listen_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let backend_primary: SocketAddr = format!("127.0.0.1:{}", backend_port).parse()?;
    let backend_secondary: SocketAddr = "127.0.0.1:3001".parse()?; // illustrative fallback

    // ─── Routing table ───────────────────────────────────────────────────────
    // Loopback (127.x.x.x) → primary backend (dynamic port supplied as arg)
    // 192.168.1.100         → secondary backend 3001 (illustrative)
    // Everything else       → Reject
    let routing = Arc::new(RoutingTable::new(RouteAction::Reject));

    routing.add_group(
        "loopback",
        IpGroup::new().add_prefix(IpPrefix::v4(127, 0, 0, 0, 8)),
    );
    routing.add_rule(
        RoutingRule::new("loopback-to-primary", RouteAction::Forward(backend_primary))
            .from_group("loopback"),
    );
    // Add a trusted single IP going to secondary.
    routing.add_rule(
        RoutingRule::new("trusted-to-secondary", RouteAction::Forward(backend_secondary))
            .from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
    );
    println!(
        "Routing table: loopback → :{} | 192.168.1.100 → :3001 | else → Reject",
        backend_port
    );

    // ─── Guards ──────────────────────────────────────────────────────────────
    let guards = GuardStackConfig {
        rate_limiter: Some(RateLimiterConfig {
            per_ip_capacity: 100,
            per_ip_refill_per_second: 50,
            global_capacity: 2000,
            global_refill_per_second: 1000,
            global_window: Duration::from_secs(10),
            global_window_limit: 5000,
            max_tracked_ips: 100_000,
        }),
        ..GuardStackConfig::default()
    };

    // ─── Metrics ─────────────────────────────────────────────────────────────
    let metrics = Arc::new(MetricsCollector::new());

    // ─── Dynamic auth handle ─────────────────────────────────────────────────
    let auth_handle = ProxyAuthHandle::new(ProxyAuth::basic("admin", "password123"));

    let config = ProxyConfig::new(listen_addr, backend_primary)
        .with_auth(ProxyAuth::basic("admin", "password123"))
        .with_buffer_size(8192)
        .with_guards(guards)
        .with_routing(routing);

    println!("Current proxy credentials: admin / password123");
    println!("Proxy will log its actual bound port on startup.");

    // Rotate credentials after 30 s (demonstrates live update).
    let auth_updater = auth_handle.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(30));
        if let Err(e) = auth_updater.set_basic("admin", "rotated-secret") {
            eprintln!("[Proxy] credential rotation failed: {}", e);
        } else {
            println!("[Proxy] credentials rotated to admin / rotated-secret");
        }
    });

    // Print metrics periodically.
    let metrics_snapshot = Arc::clone(&metrics);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(15));
        let s = metrics_snapshot.snapshot();
        println!(
            "[Metrics] TCP={} Active={} Failed={}",
            s.tcp_connections_total, s.active_connections, s.failed_connections
        );
    });

    let server = ProxyServer::new(config)
        .with_auth_handle(auth_handle)
        .with_metrics(metrics);
    server.run()?;
    Ok(())
}

// ───────────────────────────────────────────────────────────────
// Proxy server with load balancer (round-robin + consistent hash)
// ───────────────────────────────────────────────────────────────

/// Demonstrates both round-robin and sticky consistent-hash pool on different
/// routing rules pointing at two backend clusters.
fn run_proxy_server_lb() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Duration;

    let listen_addr: SocketAddr = "127.0.0.1:0".parse()?;

    // ─── Backend pools ────────────────────────────────────────────────────────
    //
    // api-cluster: three nodes, round-robin (stateless RPCs benefit from even spread).
    let api_cluster = Arc::new(BackendPool::round_robin([
        "127.0.0.1:9001".parse::<SocketAddr>()?,
        "127.0.0.1:9002".parse::<SocketAddr>()?,
        "127.0.0.1:9003".parse::<SocketAddr>()?,
    ]));

    // session-cluster: two nodes, IP-sticky consistent hash (long-lived sessions
    // must always reach the same backend).
    let session_cluster = Arc::new(BackendPool::consistent_hash(
        [
            Backend::new("127.0.0.1:9011".parse::<SocketAddr>()?).with_weight(2), // handles 2× traffic
            Backend::new("127.0.0.1:9012".parse::<SocketAddr>()?).with_weight(1),
        ],
        150,          // virtual ring nodes per unit weight
        StickyKey::Ip,
    ));

    // ─── Routing table ────────────────────────────────────────────────────────
    // /24 internal subnet → session-cluster (sticky)
    // everything else     → api-cluster (round-robin)
    let routing = Arc::new(RoutingTable::new(
        RouteAction::Pool(Arc::clone(&api_cluster)),  // default = round-robin
    ));
    routing.add_group(
        "internal",
        IpGroup::new().add_prefix(IpPrefix::v4(10, 0, 0, 0, 24)),
    );
    routing.add_rule(
        RoutingRule::new("internal-sticky", RouteAction::Pool(Arc::clone(&session_cluster)))
            .from_group("internal"),
    );

    println!("LB proxy on {}:", listen_addr);
    println!("  10.0.0.x → session-cluster (WCH, IP-sticky): :9011(w2), :9012(w1)");
    println!("  * → api-cluster (round-robin): :9001, :9002, :9003");

    // Demonstrate live backend pool modification.
    let api_pool_ref = Arc::clone(&api_cluster);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(60));
        api_pool_ref.add_backend("127.0.0.1:9004".parse::<SocketAddr>().unwrap());
        println!("[LB] scaled out api-cluster: added :9004 (now {} backends)", api_pool_ref.len());
    });

    let config = ProxyConfig::new(listen_addr, "127.0.0.1:9001".parse()?)
        .with_buffer_size(8192)
        .with_routing(routing);

    ProxyServer::new(config).run()?;
    Ok(())
}

#[cfg(feature = "async")]
fn run_proxy_server_async() -> Result<(), Box<dyn std::error::Error>> {
    use synclaire::{AsyncProxyServer, PemSource, TlsConfig};
    use std::time::Duration;
    use std::sync::Arc;

    let listen_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let backend_addr: SocketAddr = "127.0.0.1:3000".parse()?;

    let guards = GuardStackConfig {
        rate_limiter: Some(RateLimiterConfig {
            per_ip_capacity: 100,
            per_ip_refill_per_second: 50,
            global_capacity: 2000,
            global_refill_per_second: 1000,
            global_window: Duration::from_secs(10),
            global_window_limit: 5000,
            max_tracked_ips: 100_000,
        }),
        ..GuardStackConfig::default()
    };

    let auth_handle = ProxyAuthHandle::new(ProxyAuth::basic("admin", "password123"));
    let metrics = Arc::new(MetricsCollector::new());

    // Routing: loopback → backend_addr, everything else → Reject.
    let routing = Arc::new(RoutingTable::new(RouteAction::Reject));
    routing.add_group(
        "loopback",
        IpGroup::new().add_prefix(IpPrefix::v4(127, 0, 0, 0, 8)),
    );
    routing.add_rule(
        RoutingRule::new("loopback-allowed", RouteAction::Forward(backend_addr))
            .from_group("loopback"),
    );

    // TLS offload: set ENABLE_PROXY_TLS_OFFLOAD=1 + PROXY_TLS_CERT/KEY paths.
    let tls_offload = if std::env::var("ENABLE_PROXY_TLS_OFFLOAD").ok().as_deref() == Some("1") {
        let cert = std::env::var("PROXY_TLS_CERT")?;
        let key = std::env::var("PROXY_TLS_KEY")?;
        Some(
            TlsConfig::builder()
                .enabled(true)
                .certificate_chain(PemSource::file(cert))
                .private_key(PemSource::file(key))
                .build(),
        )
    } else {
        None
    };

    let mut config = ProxyConfig::new(listen_addr, backend_addr)
        .with_auth(ProxyAuth::basic("admin", "password123"))
        .with_buffer_size(8192)
        .with_guards(guards)
        .with_routing(routing);
    if let Some(tls) = tls_offload {
        config = config.with_tls_offload(tls);
        println!("Async proxy TLS offload: enabled");
    } else {
        println!("Async proxy TLS offload: disabled");
    }

    println!("Async proxy server will log its actual bound port on startup.");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let server = AsyncProxyServer::new(config)
            .with_auth_handle(auth_handle)
            .with_metrics(metrics);
        server.run().await
    })?;
    Ok(())
}

#[cfg(not(feature = "async"))]
fn run_proxy_server_async() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("proxy-server-async mode requires --features async");
    Ok(())
}

/// Proxy client that authenticates and sends payload through the proxy.
fn run_proxy_client(proxy_port: u16, payload: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", proxy_port).parse()?;
    let backend_addr: SocketAddr = "127.0.0.1:3000".parse()?;
    let payload = payload.unwrap_or_else(|| "hello from proxy client".to_string());

    let client = ProxyClient::new(proxy_addr, backend_addr)
        .with_auth(ProxyAuth::basic("admin", "password123"));

    let response = client.send_and_receive(payload.as_bytes())?;
    println!("Proxy client sent: {}", payload);
    println!("Proxy client received: {}", String::from_utf8_lossy(&response));
    Ok(())
}

/// Proxy client with intentionally bad credentials.
fn run_proxy_client_bad_credentials(proxy_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", proxy_port).parse()?;
    let backend_addr: SocketAddr = "127.0.0.1:3000".parse()?;

    let client = ProxyClient::new(proxy_addr, backend_addr)
        .with_auth(ProxyAuth::basic("admin", "wrong-password"));

    match client.send_and_receive(b"this should fail") {
        Ok(response) => {
            println!(
                "Unexpected success. Received: {}",
                String::from_utf8_lossy(&response)
            );
        }
        Err(error) => {
            println!("Expected auth failure: {}", error);
        }
    }

    Ok(())
}
