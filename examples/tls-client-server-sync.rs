// TLS Client-Server Example (Synchronous)
// This example demonstrates a synchronous TLS echo server and client.
// The server uses TLS to encrypt all communication.
//
// Usage:
//   cargo run --example tls-client-server-sync --features sync
//
// Modes:
//   demo   (default) — binds to an OS-assigned port, runs server + client in-process
//   server            — stand-alone server; prints the actual port so you can pass it to the client
//   client <port>     — connects to the server on the given port

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
        let mut stream = conn.into_stream().into_sync().expect("sync stream");
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    println!("Received {} bytes (TLS) from {}", n, peer);
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
        println!("TLS connection closed: {}", peer);
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env().init();

    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("demo");

    match mode {
        "demo" => run_demo(),
        "server" => run_server(),
        "client" => {
            let port = args
                .get(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(9003);
            run_client(port)
        }
        _ => {
            eprintln!("Usage: {} [demo|server|client] [port for client mode]", args[0]);
            Ok(())
        }
    }
}

fn run_demo() -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;

    println!("Running TLS Client-Server Demo (Synchronous)...");

    // Bind first so we know the port before the server's accept loop starts.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    println!("Server listening on port {}", port);

    let tls_config = TlsConfig::builder()
        .enabled(true)
        .certificate_chain(PemSource::file("examples/certs/server.crt"))
        .private_key(PemSource::file("examples/certs/server.key"))
        .build();

    let config = ServerConfig::builder()
        .name("tls-sync-server")
        .tls(tls_config)
        .build();

    let (shutdown, signal) = SyncServer::<EchoHandler>::shutdown_channel();
    let server = SyncServer::from_listener(listener, config, EchoHandler);

    let server_thread = thread::spawn(move || {
        server.run_until_shutdown(signal).unwrap_or_else(|e| eprintln!("Server error: {}", e));
    });

    run_client(port).unwrap_or_else(|e| eprintln!("Client error: {}", e));

    shutdown.shutdown();
    server_thread.join().ok();
    Ok(())
}

fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting TLS Echo Server (Synchronous)...");

    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    println!("Server listening on port {}", port);

    let tls_config = TlsConfig::builder()
        .enabled(true)
        .certificate_chain(PemSource::file("examples/certs/server.crt"))
        .private_key(PemSource::file("examples/certs/server.key"))
        .build();

    let config = ServerConfig::builder()
        .name("tls-sync-server")
        .tls(tls_config)
        .build();

    SyncServer::from_listener(listener, config, EchoHandler).run()?;
    Ok(())
}

fn run_client(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;
    use std::time::Duration;

    println!("Connecting to TLS Echo Server (Synchronous) on port {}...", port);

    // Give server time to start
    thread::sleep(Duration::from_millis(100));

    let tls_config = TlsConfig::builder()
        .enabled(true)
        .server_name("localhost")
        .trust_anchor(PemSource::file("examples/certs/server.crt"))
        .build();

    let config = ClientConfig::builder()
        .connect_addr(format!("127.0.0.1:{}", port).parse()?)
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
