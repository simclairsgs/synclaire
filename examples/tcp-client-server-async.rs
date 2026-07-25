// TCP Client-Server Example (Asynchronous)
// This example demonstrates a simple asynchronous TCP echo server and client using Tokio.
//
// Usage:
//   cargo run --example tcp-client-server-async --features async
//
// In separate terminals:
//   Terminal 1: cargo run --example tcp-client-server-async --features async -- server
//   Terminal 2: cargo run --example tcp-client-server-async --features async -- client <port>

use std::env;
use synclaire::{config::ServerConfig, handler::ConnectionHandler, AsyncServer};

struct EchoHandler;

impl ConnectionHandler for EchoHandler {
    fn handle<'a>(
        &'a self,
        mut conn: synclaire::Connection,
    ) -> synclaire::handler::HandlerFuture<'a> {
        Box::pin(async move {
            let mut buf = [0u8; 1024];

            loop {
                match conn.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        println!("Received {} bytes from {}", n, conn.peer_addr());
                        conn.write_all(&buf[..n]).await?;
                    }
                    Err(e) => {
                        eprintln!("Read error: {}", e);
                        break;
                    }
                }
            }

            println!("Connection closed: {}", conn.peer_addr());
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
        "client" => {
            let port = args
                .get(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(9002);
            run_client(port).await
        }
        _ => {
            eprintln!("Usage: {} [server|client] [port for client mode]", args[0]);
            Ok(())
        }
    }
}

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting TCP Echo Server (Asynchronous)...");

    let config = ServerConfig::builder()
        .name("tcp-async-server")
        .bind_addr("127.0.0.1:0".parse()?)
        .build();

    let server = AsyncServer::new(config, EchoHandler);
    server.run().await?;

    Ok(())
}

async fn run_client(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to TCP Echo Server (Asynchronous) on port {}...", port);

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let config = synclaire::config::ClientConfig::builder()
        .connect_addr(format!("127.0.0.1:{}", port).parse()?)
        .build();

    let mut conn = synclaire::AsyncClient::new(config).connect().await?;
    println!("Connected to server: {}", conn.peer_addr());

    // Send test message
    let message = b"Hello from TCP Async Client!";
    conn.write_all(message).await?;

    // Read echo response
    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).await?;
    println!("Received: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
