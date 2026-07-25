// Mutual TLS (mTLS) Client-Server Example (Synchronous)
// This example demonstrates synchronous mTLS where both client and server authenticate each other.
// Both client and server present certificates and verify the other's certificate.
//
// Usage:
//   cargo run --example mtls-client-server-sync --features sync
//
// In separate terminals:
//   Terminal 1: cargo run --example mtls-client-server-sync --features sync -- server
//   Terminal 2: cargo run --example mtls-client-server-sync --features sync -- client <port>

use std::env;

use std::io::{Read, Write};
use synclaire::{
    config::{ClientConfig, ServerConfig, TlsConfig},
    handler::SyncConnectionHandler,
    PemSource, SyncServer, SynError,
};

struct EchoHandler;

impl SyncConnectionHandler for EchoHandler {
    fn handle(&self, conn: synclaire::Connection) -> synclaire::error::Result<()> {
        let peer = conn.peer_addr();
        if conn.is_tls() {
            println!("Accepted mTLS connection from {} (client authenticated)", peer);
        }
        let mut stream = conn.into_stream().into_sync().expect("sync stream");
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    println!("Received {} bytes (mTLS) from {}", n, peer);
                    if let Err(e) = stream.write_all(&buf[..n]) {
                        eprintln!("Write error: {}", e);
                        return Err(e.into());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut
                       || e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    eprintln!("Read error: {}", e);
                    break;
                }
            }
        }
        println!("mTLS connection closed: {}", peer);
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env().init();

    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("server");

    match mode {
        "server" => run_server(),
        "client" => {
            let port = args
                .get(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(9005);
            run_client(port)
        }
        _ => {
            eprintln!("Usage: {} [server|client] [port for client mode]", args[0]);
            Ok(())
        }
    }
}

fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting mTLS Echo Server (Synchronous - Mutual Authentication)...");

    let tls_config = TlsConfig::builder()
        .enabled(true)
        .certificate_chain(PemSource::file("examples/certs/server.crt"))
        .private_key(PemSource::file("examples/certs/server.key"))
        .trust_anchor(PemSource::file("examples/certs/client.crt"))
        .require_client_auth(true)
        .build();

    let config = ServerConfig::builder()
        .name("mtls-sync-server")
        .bind_addr("127.0.0.1:0".parse()?)
        .tls(tls_config)
        .build();

    let server = SyncServer::new(config, EchoHandler);
    server.run()?;

    Ok(())
}

fn run_client(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;
    use std::time::Duration;

    println!("Connecting to mTLS Echo Server (Synchronous - Mutual Authentication) on port {}...", port);

    // Give server time to start
    thread::sleep(Duration::from_millis(500));

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

    let mut conn = synclaire::SyncClient::new(config).connect()?;
    println!("Connected via mTLS to server: {} (server verified)", conn.peer_addr());

    let message = b"Hello from mTLS Sync Client (mutually authenticated)!";
    futures::executor::block_on(async {
        conn.write_all(message).await?;
        let mut buf = [0u8; 1024];
        let n = conn.read(&mut buf).await?;
        println!("Received (mTLS): {}", String::from_utf8_lossy(&buf[..n]));
        Ok::<(), SynError>(())
    })?;

    Ok(())
}
