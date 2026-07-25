use synclaire::{
    handler::{Connection, ConnectionMetadata},
    AsyncStream, ServerConfig, SynError,
};

fn make_metadata(addr: &str) -> ConnectionMetadata {
    ConnectionMetadata::new(addr.parse().expect("valid addr"), None, false)
}

// ------------------------------------------------------------------
// AsyncStream concrete type tests
// ------------------------------------------------------------------

#[cfg(feature = "async")]
#[tokio::test]
async fn async_stream_tcp_variant_is_not_tls() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let _client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let (stream, peer) = listener.accept().await.expect("accept");

    let conn = Connection::from_async_tcp(make_metadata(&peer.to_string()), stream);

    assert!(!conn.is_tls(), "TCP connection should not report is_tls");
    assert!(conn.async_stream().as_tcp().is_some(), "should expose TcpStream");
    assert!(conn.async_stream().as_server_tls().is_none());
    assert!(conn.async_stream().as_client_tls().is_none());
}

#[cfg(feature = "async")]
#[tokio::test]
async fn async_stream_tcp_ref_gives_real_socket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let _client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let (stream, peer) = listener.accept().await.expect("accept");

    let conn = Connection::from_async_tcp(make_metadata(&peer.to_string()), stream);

    // tcp() on AsyncStream returns the underlying socket regardless of TLS wrapping.
    let tcp_ref = conn.async_stream().tcp();
    assert!(tcp_ref.local_addr().is_ok(), "socket should have a local addr");
}

#[cfg(feature = "async")]
#[tokio::test]
async fn async_stream_can_be_moved_out() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let _client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let (stream, peer) = listener.accept().await.expect("accept");

    let conn = Connection::from_async_tcp(make_metadata(&peer.to_string()), stream);
    let raw = conn.into_stream().into_async().expect("async stream");

    // Direct I/O on the moved-out stream.
    match raw {
        AsyncStream::Tcp(tcp) => {
            assert!(tcp.peer_addr().is_ok());
        }
        _ => panic!("expected TCP variant"),
    }
}

// ------------------------------------------------------------------
// ConnectionStream unified wrapper tests
// ------------------------------------------------------------------

#[cfg(feature = "async")]
#[tokio::test]
async fn connection_stream_is_tls_delegates_to_variant() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let _client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let (stream, peer) = listener.accept().await.expect("accept");

    let conn = Connection::from_async_tcp(make_metadata(&peer.to_string()), stream);
    assert!(!conn.stream().is_tls());
    assert!(conn.stream().as_async().is_some());
    assert!(conn.stream().as_async().unwrap().as_tcp().is_some());
}

// ------------------------------------------------------------------
// AcceptMode and mixed-mode detection logic
// ------------------------------------------------------------------

#[test]
fn accept_mode_default_is_tcp() {
    use synclaire::AcceptMode;
    let config = ServerConfig::default();
    assert_eq!(config.accept_mode, AcceptMode::Tcp);
}

#[test]
fn accept_mode_builder_sets_tls_and_mixed() {
    use synclaire::AcceptMode;

    let tls_config = ServerConfig::builder()
        .accept_mode(AcceptMode::Tls)
        .build();
    assert_eq!(tls_config.accept_mode, AcceptMode::Tls);

    let mixed_config = ServerConfig::builder()
        .accept_mode(AcceptMode::Mixed)
        .build();
    assert_eq!(mixed_config.accept_mode, AcceptMode::Mixed);
}

// ------------------------------------------------------------------
// Handler works with the concrete stream (functional smoke test)
// ------------------------------------------------------------------

#[cfg(feature = "async")]
#[tokio::test]
async fn handler_closure_receives_concrete_tcp_stream() {
    use synclaire::AsyncServer;
    use std::sync::{Arc, Mutex};

    let got_tls: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let got_tls_clone = Arc::clone(&got_tls);

    // Pick an ephemeral port and bind before the server so we know the address.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = listener.local_addr().expect("local addr");
    drop(listener);

    let config = ServerConfig::builder()
        .bind_addr(server_addr)
        .max_connections(1)
        .build();

    // Run the server for exactly one connection then we are done.
    let handle = tokio::spawn(async move {
        AsyncServer::new(config, move |conn: synclaire::Connection| {
            let got_tls = Arc::clone(&got_tls_clone);
            async move {
                *got_tls.lock().unwrap() = Some(conn.is_tls());
                Ok::<(), SynError>(())
            }
        })
        .run()
        .await
    });

    // Give the server a moment to start.
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    // Connect as a plain TCP client.
    let mut client = tokio::net::TcpStream::connect(server_addr).await.expect("connect");
    tokio::io::AsyncWriteExt::shutdown(&mut client).await.ok();

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    handle.abort();

    // The handler should have seen a non-TLS connection.
    let is_tls = got_tls.lock().unwrap().unwrap_or(true);
    assert!(!is_tls, "plain TCP should not report is_tls");
}
