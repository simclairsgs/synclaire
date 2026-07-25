// TLS Client-Server Example (Asynchronous)
// This example demonstrates an asynchronous TLS echo server and client using Tokio.
// The server uses TLS to encrypt all communication.
//
// Usage:
//   cargo run --example tls-client-server-async --features async
//
// In separate terminals:
//   Terminal 1: cargo run --example tls-client-server-async --features async -- server
//   Terminal 2: cargo run --example tls-client-server-async --features async -- client

use std::env;
use synclaire::{
    config::{ClientConfig, ServerConfig, TlsConfig},
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
            let mut buf = [0u8; 1024];

            loop {
                match conn.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        println!("Received {} bytes (TLS) from {}", n, conn.peer_addr());
                        conn.write_all(&buf[..n]).await?;
                    }
                    Err(e) => {
                        eprintln!("Read error: {}", e);
                        break;
                    }
                }
            }

            println!("TLS connection closed: {}", conn.peer_addr());
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
        "client" => run_client().await,
        _ => {
            eprintln!("Usage: {} [server|client]", args[0]);
            Ok(())
        }
    }
}

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting TLS Echo Server (Asynchronous)...");

    let tls_config = TlsConfig::builder()
        .enabled(true)
        .certificate_chain(PemSource::file("examples/certs/server.crt"))
        .private_key(PemSource::file("examples/certs/server.key"))
        .build();

    let config = ServerConfig::builder()
        .name("tls-async-server")
        .bind_addr("127.0.0.1:9004".parse()?)
        .tls(tls_config)
        .build();

    let server = AsyncServer::new(config, EchoHandler);
    server.run().await?;

    Ok(())
}

async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to TLS Echo Server (Asynchronous)...");

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let tls_config = TlsConfig::builder()
        .enabled(true)
        .server_name("localhost")
        .trust_anchor(PemSource::file("examples/certs/server.crt"))
        .build();

    let config = ClientConfig::builder()
        .connect_addr("127.0.0.1:9004".parse()?)
        .tls(tls_config)
        .build();

    let mut conn = synclaire::AsyncClient::new(config).connect().await?;
    println!("Connected via TLS to server: {}", conn.peer_addr());

    // Send test message over TLS
    let message = b"Hello from TLS Async Client!";
    conn.write_all(message).await?;

    // Read echo response
    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).await?;
    println!("Received (TLS): {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
