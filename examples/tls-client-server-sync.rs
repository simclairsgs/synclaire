// TLS Client-Server Example (Synchronous)
// This example demonstrates a synchronous TLS echo server and client.
// The server uses TLS to encrypt all communication.
//
// Usage:
//   cargo run --example tls-client-server-sync --features sync
//
// In separate terminals:
//   Terminal 1: cargo run --example tls-client-server-sync --features sync -- server
//   Terminal 2: cargo run --example tls-client-server-sync --features sync -- client

use std::env;

use synclaire::{
    config::{ClientConfig, ServerConfig, TlsConfig},
    handler::ConnectionHandler,
    PemSource, SyncServer, SynError,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env().init();

    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("server");

    match mode {
        "server" => run_server(),
        "client" => run_client(),
        _ => {
            eprintln!("Usage: {} [server|client]", args[0]);
            Ok(())
        }
    }
}

fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting TLS Echo Server (Synchronous)...");

    let tls_config = TlsConfig::builder()
        .enabled(true)
        .certificate_chain(PemSource::file("examples/certs/server.crt"))
        .private_key(PemSource::file("examples/certs/server.key"))
        .build();

    let config = ServerConfig::builder()
        .name("tls-sync-server")
        .bind_addr("127.0.0.1:9003".parse()?)
        .tls(tls_config)
        .build();

    let server = SyncServer::new(config, EchoHandler);
    server.run()?;

    Ok(())
}

fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;
    use std::time::Duration;

    println!("Connecting to TLS Echo Server (Synchronous)...");

    // Give server time to start
    thread::sleep(Duration::from_millis(500));

    let tls_config = TlsConfig::builder()
        .enabled(true)
        .server_name("localhost")
        .trust_anchor(PemSource::file("examples/certs/server.crt"))
        .build();

    let config = ClientConfig::builder()
        .connect_addr("127.0.0.1:9003".parse()?)
        .tls(tls_config)
        .build();

    let mut conn = synclaire::SyncClient::new(config).connect()?;
    println!("Connected via TLS to server: {}", conn.peer_addr());

    let message = b"Hello from TLS Sync Client!";
    futures::executor::block_on(async {
        conn.write_all(message).await?;
        let mut buf = [0u8; 1024];
        let n = conn.read(&mut buf).await?;
        println!("Received (TLS): {}", String::from_utf8_lossy(&buf[..n]));
        Ok::<(), SynError>(())
    })?;

    Ok(())
}
