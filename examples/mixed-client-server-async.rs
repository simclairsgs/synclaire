// Mixed-Mode (TCP + TLS) Client-Server Example (Asynchronous)
// This example demonstrates a server that accepts both TCP and TLS connections on the same port
// using automatic protocol detection. The server automatically detects whether the client is
// connecting with TLS or plain TCP based on the first byte received (0x16 = TLS ClientHello).
//
// Usage:
//   cargo run --example mixed-client-server-async --features async
//
// In separate terminals:
//   Terminal 1: cargo run --example mixed-client-server-async --features async -- server
//   Terminal 2: cargo run --example mixed-client-server-async --features async -- client-tcp
//   Terminal 3: cargo run --example mixed-client-server-async --features async -- client-tls

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
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("server");

    match mode {
        "server" => run_server().await,
        "client-tcp" => run_client_tcp().await,
        "client-tls" => run_client_tls().await,
        _ => {
            eprintln!(
                "Usage: {} [server|client-tcp|client-tls]",
                args[0]
            );
            Ok(())
        }
    }
}

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Mixed-Mode Echo Server (Asynchronous - TCP + TLS auto-detection)...");

    let tls_config = TlsConfig::builder()
        .enabled(false)
        .certificate_chain(PemSource::file("examples/certs/server.crt"))
        .private_key(PemSource::file("examples/certs/server.key"))
        .build();

    let config = ServerConfig::builder()
        .name("mixed-async-server")
        .bind_addr("127.0.0.1:9008".parse()?)
        .tls(tls_config)
        .accept_mode(AcceptMode::Mixed)
        .build();

    let server = AsyncServer::new(config, EchoHandler);
    server.run().await?;

    Ok(())
}

async fn run_client_tcp() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to Mixed-Mode Server (Asynchronous) with plain TCP...");

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let config = ClientConfig::builder()
        .connect_addr("127.0.0.1:9008".parse()?)
        .build();

    let mut conn = synclaire::AsyncClient::new(config).connect().await?;
    println!("Connected (TCP) to server: {}", conn.peer_addr());

    // Send test message over plain TCP
    let message = b"Hello from Mixed-Mode Async Client (TCP)!";
    conn.write_all(message).await?;

    // Read echo response
    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).await?;
    println!("Received (TCP): {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}

async fn run_client_tls() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to Mixed-Mode Server (Asynchronous) with TLS...");

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let tls_config = TlsConfig::builder()
        .enabled(true)
        .server_name("localhost")
        .trust_anchor(PemSource::file("examples/certs/server.crt"))
        .build();

    let config = ClientConfig::builder()
        .connect_addr("127.0.0.1:9008".parse()?)
        .tls(tls_config)
        .build();

    let mut conn = synclaire::AsyncClient::new(config).connect().await?;
    println!("Connected (TLS) to server: {}", conn.peer_addr());

    // Send test message over TLS
    let message = b"Hello from Mixed-Mode Async Client (TLS)!";
    conn.write_all(message).await?;

    // Read echo response
    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).await?;
    println!("Received (TLS): {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
