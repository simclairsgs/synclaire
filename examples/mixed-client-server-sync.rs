use std::env;

use synclaire::{
    config::{AcceptMode, ClientConfig, ServerConfig, TlsConfig},
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env().init();

    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("server");

    match mode {
        "server" => run_server(),
        "client-tcp" => run_client_tcp(),
        "client-tls" => run_client_tls(),
        _ => {
            eprintln!("Usage: {} [server|client-tcp|client-tls]", args[0]);
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
        .bind_addr("127.0.0.1:9007".parse()?)
        .tls(tls_config)
        .accept_mode(AcceptMode::Mixed)
        .build();

    let server = SyncServer::new(config, EchoHandler);
    server.run()?;
    Ok(())
}

fn run_client_tcp() -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;
    use std::time::Duration;

    println!("Connecting to Mixed-Mode Server (Synchronous) with plain TCP...");
    thread::sleep(Duration::from_millis(500));

    let config = ClientConfig::builder()
        .connect_addr("127.0.0.1:9007".parse()?)
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

fn run_client_tls() -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;
    use std::time::Duration;

    println!("Connecting to Mixed-Mode Server (Synchronous) with TLS...");
    thread::sleep(Duration::from_millis(500));

    let tls_config = TlsConfig::builder()
        .enabled(true)
        .server_name("localhost")
        .trust_anchor(PemSource::file("examples/certs/server.crt"))
        .build();

    let config = ClientConfig::builder()
        .connect_addr("127.0.0.1:9007".parse()?)
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
