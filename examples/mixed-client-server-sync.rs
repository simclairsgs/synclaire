use std::env;

use std::io::{Read, Write};
use synclaire::{
    config::{AcceptMode, ClientConfig, ServerConfig, TlsConfig},
    handler::SyncConnectionHandler,
    PemSource, SyncServer, SynError,
};

struct EchoHandler;

impl SyncConnectionHandler for EchoHandler {
    fn handle(&self, conn: synclaire::Connection) -> synclaire::error::Result<()> {
        let peer = conn.peer_addr();
        let protocol = if conn.is_tls() { "TLS" } else { "TCP" };
        println!("Accepted {} connection from {}", protocol, peer);
        let mut stream = conn.into_stream().into_sync().expect("sync stream");
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    println!("Received {} bytes ({}) from {}", n, protocol, peer);
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
        println!("{} connection closed: {}", protocol, peer);
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env().init();

    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("server");
    let port = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(9007);

    match mode {
        "server" => run_server(),
        "client-tcp" => run_client_tcp(port),
        "client-tls" => run_client_tls(port),
        _ => {
            eprintln!("Usage: {} [server|client-tcp|client-tls] [port for client modes]", args[0]);
            Ok(())
        }
    }
}

fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Mixed-Mode Echo Server (Synchronous - TCP + TLS auto-detection)...");

    let tls_config = TlsConfig::builder()
        .enabled(false)
        .certificate_chain(PemSource::file("examples/certs/server.crt"))
        .private_key(PemSource::file("examples/certs/server.key"))
        .build();

    let config = ServerConfig::builder()
        .name("mixed-sync-server")
        .bind_addr("127.0.0.1:0".parse()?)
        .tls(tls_config)
        .accept_mode(AcceptMode::Mixed)
        .build();

    let server = SyncServer::new(config, EchoHandler);
    server.run()?;
    Ok(())
}

fn run_client_tcp(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;
    use std::time::Duration;

    println!("Connecting to Mixed-Mode Server (Synchronous) with plain TCP on port {}...", port);
    thread::sleep(Duration::from_millis(500));

    let config = ClientConfig::builder()
        .connect_addr(format!("127.0.0.1:{}", port).parse()?)
        .build();

    let mut conn = synclaire::SyncClient::new(config).connect()?;
    println!("Connected (TCP) to server: {}", conn.peer_addr());

    let message = b"Hello from Mixed-Mode Sync Client (TCP)!";
    futures::executor::block_on(async {
        conn.write_all(message).await?;
        let mut buf = [0u8; 1024];
        let n = conn.read(&mut buf).await?;
        println!("Received (TCP): {}", String::from_utf8_lossy(&buf[..n]));
        Ok::<(), SynError>(())
    })?;

    Ok(())
}

fn run_client_tls(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;
    use std::time::Duration;

    println!("Connecting to Mixed-Mode Server (Synchronous) with TLS on port {}...", port);
    thread::sleep(Duration::from_millis(500));

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
    println!("Connected (TLS) to server: {}", conn.peer_addr());

    let message = b"Hello from Mixed-Mode Sync Client (TLS)!";
    futures::executor::block_on(async {
        conn.write_all(message).await?;
        let mut buf = [0u8; 1024];
        let n = conn.read(&mut buf).await?;
        println!("Received (TLS): {}", String::from_utf8_lossy(&buf[..n]));
        Ok::<(), SynError>(())
    })?;

    Ok(())
}
