// Async mixed-mode server: accepts both TCP and TLS on the same port.
//   cd examples && sh generate-certs.sh && cd ..
//   cargo run --example mixed-client-server-async

use std::env;
use synclaire::{
    config::{AcceptMode, ClientConfig, ServerConfig, TlsConfig},
    handler::ConnectionHandler,
    AsyncServer, PemSource,
};

struct EchoHandler;

impl ConnectionHandler for EchoHandler {
    fn handle<'a>(
        &'a self,
        mut conn: synclaire::Connection,
    ) -> synclaire::handler::HandlerFuture<'a> {
        Box::pin(async move {
            let protocol = if conn.is_tls() { "TLS" } else { "TCP" };
            println!("Accepted {} connection from {}", protocol, conn.peer_addr());

            let mut buf = [0u8; 1024];
            loop {
                match conn.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        println!("Received {} bytes ({}) from {}", n, protocol, conn.peer_addr());
                        conn.write_all(&buf[..n]).await?;
                    }
                    Err(e) => {
                        eprintln!("Read error: {}", e);
                        break;
                    }
                }
            }

            println!("{} connection closed: {}", protocol, conn.peer_addr());
            Ok(())
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env().init();

    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("demo");
    let port = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(9008);

    match mode {
        "demo" => run_demo().await,
        "server" => run_server().await,
        "client-tcp" => run_client_tcp(port).await,
        "client-tls" => run_client_tls(port).await,
        _ => {
            eprintln!(
                "Usage: {} [demo|server|client-tcp|client-tls] [port for client modes]",
                args[0]
            );
            Ok(())
        }
    }
}

async fn run_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("Running Mixed-Mode Client-Server Demo (Asynchronous)...");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    println!("Server listening on port {port}");

    let tls_config = TlsConfig::builder()
        .enabled(false)
        .certificate_chain(PemSource::file("examples/certs/server.crt"))
        .private_key(PemSource::file("examples/certs/server.key"))
        .build();

    let config = ServerConfig::builder()
        .name("mixed-async-server")
        .tls(tls_config)
        .accept_mode(AcceptMode::Mixed)
        .build();

    let (shutdown, rx) = AsyncServer::<EchoHandler>::shutdown_channel();
    let server = AsyncServer::from_listener(listener, config, EchoHandler);
    tokio::spawn(async move {
        server.run_until_shutdown(rx).await.ok();
    });

    run_client_tcp(port).await?;
    run_client_tls(port).await?;
    shutdown.shutdown()?;
    Ok(())
}

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Mixed-Mode Echo Server (Asynchronous - TCP + TLS auto-detection)...");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    println!("Server listening on port {port}");

    let tls_config = TlsConfig::builder()
        .enabled(false)
        .certificate_chain(PemSource::file("examples/certs/server.crt"))
        .private_key(PemSource::file("examples/certs/server.key"))
        .build();

    let config = ServerConfig::builder()
        .name("mixed-async-server")
        .tls(tls_config)
        .accept_mode(AcceptMode::Mixed)
        .build();

    AsyncServer::from_listener(listener, config, EchoHandler).run().await?;
    Ok(())
}

async fn run_client_tcp(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to Mixed-Mode Server (Asynchronous) with plain TCP on port {}...", port);

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let config = ClientConfig::builder()
        .connect_addr(format!("127.0.0.1:{}", port).parse()?)
        .build();

    let mut conn = synclaire::AsyncClient::new(config).connect().await?;
    println!("Connected (TCP) to server: {}", conn.peer_addr());

    let message = b"Hello from Mixed-Mode Async Client (TCP)!";
    conn.write_all(message).await?;

    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).await?;
    println!("Received (TCP): {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}

async fn run_client_tls(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to Mixed-Mode Server (Asynchronous) with TLS on port {}...", port);

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let tls_config = TlsConfig::builder()
        .enabled(true)
        .server_name("localhost")
        .trust_anchor(PemSource::file("examples/certs/ca.crt"))
        .build();

    let config = ClientConfig::builder()
        .connect_addr(format!("127.0.0.1:{}", port).parse()?)
        .tls(tls_config)
        .build();

    let mut conn = synclaire::AsyncClient::new(config).connect().await?;
    println!("Connected (TLS) to server: {}", conn.peer_addr());

    let message = b"Hello from Mixed-Mode Async Client (TLS)!";
    conn.write_all(message).await?;

    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).await?;
    println!("Received (TLS): {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
