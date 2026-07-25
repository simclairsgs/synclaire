// Mutual TLS (mTLS) Client-Server Example (Asynchronous)
// This example demonstrates asynchronous mTLS where both client and server authenticate each other.
// Both client and server present certificates and verify the other's certificate.
//
// Usage:
//   cargo run --example mtls-client-server-async --features async
//
// In separate terminals:
//   Terminal 1: cargo run --example mtls-client-server-async --features async -- server
//   Terminal 2: cargo run --example mtls-client-server-async --features async -- client <port>

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

            if conn.is_tls() {
                println!("Accepted mTLS connection from {} (client authenticated)", conn.peer_addr());
            }

            loop {
                match conn.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        println!("Received {} bytes (mTLS) from {}", n, conn.peer_addr());
                        conn.write_all(&buf[..n]).await?;
                    }
                    Err(e) => {
                        eprintln!("Read error: {}", e);
                        break;
                    }
                }
            }

            println!("mTLS connection closed: {}", conn.peer_addr());
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
                .unwrap_or(9006);
            run_client(port).await
        }
        _ => {
            eprintln!("Usage: {} [server|client] [port for client mode]", args[0]);
            Ok(())
        }
    }
}

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting mTLS Echo Server (Asynchronous - Mutual Authentication)...");

    let tls_config = TlsConfig::builder()
        .enabled(true)
        .certificate_chain(PemSource::file("examples/certs/server.crt"))
        .private_key(PemSource::file("examples/certs/server.key"))
        .trust_anchor(PemSource::file("examples/certs/client.crt"))
        .require_client_auth(true)
        .build();

    let config = ServerConfig::builder()
        .name("mtls-async-server")
        .bind_addr("127.0.0.1:0".parse()?)
        .tls(tls_config)
        .build();

    let server = AsyncServer::new(config, EchoHandler);
    server.run().await?;

    Ok(())
}

async fn run_client(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to mTLS Echo Server (Asynchronous - Mutual Authentication) on port {}...", port);

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let tls_config = TlsConfig::builder()
        .enabled(true)
        .server_name("localhost")
        .client_certificate_chain(PemSource::file("examples/certs/client.crt"))
        .client_private_key(PemSource::file("examples/certs/client.key"))
        .trust_anchor(PemSource::file("examples/certs/server.crt"))
        .build();

    let config = ClientConfig::builder()
        .connect_addr(format!("127.0.0.1:{}", port).parse()?)
        .tls(tls_config)
        .build();

    let mut conn = synclaire::AsyncClient::new(config).connect().await?;
    println!("Connected via mTLS to server: {} (server verified)", conn.peer_addr());

    // Send test message over mTLS
    let message = b"Hello from mTLS Async Client (mutually authenticated)!";
    conn.write_all(message).await?;

    // Read echo response
    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).await?;
    println!("Received (mTLS): {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
