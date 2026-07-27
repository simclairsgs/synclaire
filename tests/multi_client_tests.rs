use std::time::Duration;

// ---------------------------------------------------------------------------
// Async: multiple clients served concurrently
// ---------------------------------------------------------------------------

#[cfg(feature = "async")]
#[tokio::test]
async fn async_server_handles_multiple_clients() {
    use synclaire::{
        handler::{Connection, ConnectionHandler, HandlerFuture},
        server::async_server::AsyncServer,
        ServerConfig,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Echo;

    impl ConnectionHandler for Echo {
        fn handle<'a>(&'a self, mut conn: Connection) -> HandlerFuture<'a> {
            Box::pin(async move {
                let mut buf = [0u8; 256];
                loop {
                    let n = conn.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    conn.write_all(&buf[..n]).await?;
                }
                Ok(())
            })
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let config = ServerConfig::builder().bind_addr(addr).build();
    let (shutdown_tx, shutdown_rx) = AsyncServer::<Echo>::shutdown_channel();

    tokio::spawn(async move {
        AsyncServer::from_listener(listener, config, Echo)
            .run_until_shutdown(shutdown_rx)
            .await
            .ok();
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut handles = vec![];
    for i in 0u8..5 {
        let handle = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let msg = format!("hello from client {i}");
            stream.write_all(msg.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();

            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            assert_eq!(response, msg);
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }

    shutdown_tx.shutdown().ok();
}

// ---------------------------------------------------------------------------
// Sync: multiple clients served sequentially
// ---------------------------------------------------------------------------

#[cfg(feature = "sync")]
#[test]
fn sync_server_handles_multiple_clients() {
    use std::io::{Read, Write};
    use std::thread;
    use synclaire::{
        handler::{Connection, SyncConnectionHandler},
        server::sync_server::SyncServer,
        ServerConfig, SynError,
    };

    struct Echo;

    impl SyncConnectionHandler for Echo {
        fn handle(&self, conn: Connection) -> Result<(), SynError> {
            let mut stream = conn.into_stream().into_sync().expect("sync stream");
            let mut buf = [0u8; 256];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => stream.write_all(&buf[..n])?,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::TimedOut
                            || e.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        break
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        }
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let config = ServerConfig::builder().bind_addr(addr).build();
    let (shutdown_tx, shutdown_rx) = SyncServer::<Echo>::shutdown_channel();

    let server = thread::spawn(move || {
        SyncServer::from_listener(listener, config, Echo)
            .run_until_shutdown(shutdown_rx)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    for i in 0u8..3 {
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        let msg = format!("hello from client {i}");
        stream.write_all(msg.as_bytes()).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();

        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert_eq!(response, msg);
    }

    shutdown_tx.shutdown();
    server.join().ok();
}

// ---------------------------------------------------------------------------
// Async: guard stack rejects excess connections (throttle per-IP)
// ---------------------------------------------------------------------------

#[cfg(feature = "async")]
#[tokio::test]
async fn async_server_guards_reject_excess_clients() {
    use synclaire::{
        config::GuardStackConfig,
        guard::ThrottleConfig,
        handler::{Connection, ConnectionHandler, HandlerFuture},
        server::async_server::AsyncServer,
        ServerConfig,
    };
    use tokio::io::AsyncReadExt;

    struct Hold;

    impl ConnectionHandler for Hold {
        fn handle<'a>(&'a self, _conn: Connection) -> HandlerFuture<'a> {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            })
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let config = ServerConfig::builder()
        .bind_addr(addr)
        .guards(GuardStackConfig {
            throttle: Some(ThrottleConfig {
                max_connections_per_ip: 2,
                max_connections_global: 100,
            }),
            ..Default::default()
        })
        .build();

    let (shutdown_tx, shutdown_rx) = AsyncServer::<Hold>::shutdown_channel();

    tokio::spawn(async move {
        AsyncServer::from_listener(listener, config, Hold)
            .run_until_shutdown(shutdown_rx)
            .await
            .ok();
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let _c1 = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    let _c2 = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let mut c3 = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut buf = [0u8; 1];
    let n = c3.read(&mut buf).await.unwrap_or(0);
    assert_eq!(n, 0, "third connection should be rejected (guard throttle)");

    shutdown_tx.shutdown().ok();
}

// ---------------------------------------------------------------------------
// IPv6 guard tests
// ---------------------------------------------------------------------------

#[test]
fn guards_work_with_ipv6_addresses() {
    use synclaire::guard::*;

    let v6_ctx = |port: u16| -> GuardContext {
        let addr = format!("[::1]:{port}").parse().unwrap();
        GuardContext::new(addr, None, false)
    };

    let limiter = RateLimiter::new(RateLimiterConfig {
        per_ip_capacity: 2,
        per_ip_refill_per_second: 0,
        global_capacity: 100,
        global_refill_per_second: 0,
        global_window: Duration::from_secs(60),
        global_window_limit: 100,
        max_tracked_ips: 1000,
    });

    assert!(Guard::on_reserve(&limiter, &v6_ctx(1)).is_ok());
    assert!(Guard::on_reserve(&limiter, &v6_ctx(2)).is_ok());
    assert!(
        Guard::on_reserve(&limiter, &v6_ctx(3)).is_err(),
        "should be rate limited"
    );

    let throttle = Throttle::new(ThrottleConfig {
        max_connections_per_ip: 1,
        max_connections_global: 100,
    });

    let ctx = v6_ctx(10);
    assert!(Guard::on_reserve(&throttle, &ctx).is_ok());
    assert!(
        Guard::on_reserve(&throttle, &ctx).is_err(),
        "per-IP limit hit"
    );
    Guard::on_close(&throttle, &ctx);
    assert!(
        Guard::on_reserve(&throttle, &ctx).is_ok(),
        "released after close"
    );

    let ban = IpBan::new(IpBanConfig {});
    let v6_ip = "::1".parse().unwrap();
    assert!(!ban.is_banned(&v6_ip));
    ban.ban(v6_ip);
    assert!(ban.is_banned(&v6_ip));
    ban.unban(&v6_ip);
    assert!(!ban.is_banned(&v6_ip));
}

#[test]
fn routing_ipv6_prefix_matching() {
    use std::net::IpAddr;
    use synclaire::routing::IpPrefix;

    let prefix = IpPrefix::v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32);

    let inside: IpAddr = "2001:db8::1".parse().unwrap();
    let also_inside: IpAddr = "2001:db8:1::ffff".parse().unwrap();
    let outside: IpAddr = "2001:db9::1".parse().unwrap();

    assert!(prefix.contains(inside));
    assert!(prefix.contains(also_inside));
    assert!(!prefix.contains(outside));

    let v4: IpAddr = "192.168.1.1".parse().unwrap();
    assert!(!prefix.contains(v4), "v6 prefix should not match v4 addr");
}
