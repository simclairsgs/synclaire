use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::Duration,
};

use log::info;

use crate::{
    config::{AcceptMode, ServerConfig},
    guard::GuardContext,
    handler::{attach_guard_session, Connection, SyncConnectionHandler},
    server::{build_guard_stack, tcp},
    SynError,
};
#[cfg(any(feature = "rustls-backend", feature = "aws-lc-backend"))]
use crate::server::tls;

#[derive(Clone, Debug)]
pub struct SyncServerShutdown {
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl SyncServerShutdown {
    pub fn shutdown(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Clone, Debug)]
pub struct SyncShutdownSignal {
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl SyncShutdownSignal {
    fn is_shutdown_requested(&self) -> bool {
        self.stop.load(std::sync::atomic::Ordering::SeqCst)
    }
}

type Job = Box<dyn FnOnce() + Send + 'static>;

struct ThreadPool {
    sender: mpsc::Sender<Job>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl ThreadPool {
    fn new(size: usize) -> Self {
        let (sender, receiver) = mpsc::channel::<Job>();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(size);

        for _ in 0..size.max(1) {
            let receiver = Arc::clone(&receiver);
            workers.push(thread::spawn(move || loop {
                let job = {
                    let guard = receiver.lock().expect("worker receiver poisoned");
                    guard.recv()
                };

                match job {
                    Ok(job) => job(),
                    Err(_) => break,
                }
            }));
        }

        Self { sender, workers }
    }

    fn execute(&self, job: Job) -> Result<(), SynError> {
        self.sender.send(job).map_err(|error| SynError::runtime(error.to_string()))
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        let (replacement_sender, _replacement_receiver) = mpsc::channel::<Job>();
        let old_sender = std::mem::replace(&mut self.sender, replacement_sender);
        drop(old_sender);

        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

pub struct SyncServer<H> {
    config: ServerConfig,
    handler: Arc<H>,
    guards: crate::guard::GuardStack,
    pool: ThreadPool,
    active_connections: Arc<AtomicUsize>,
    listener: Option<std::net::TcpListener>,
}

impl<H> SyncServer<H>
where
    H: SyncConnectionHandler,
{
    pub fn shutdown_channel() -> (SyncServerShutdown, SyncShutdownSignal) {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        (
            SyncServerShutdown { stop: Arc::clone(&stop) },
            SyncShutdownSignal { stop },
        )
    }

    pub fn new(config: ServerConfig, handler: H) -> Self {
        let guards = build_guard_stack(&config.guards);
        let pool = ThreadPool::new(config.worker_threads);
        Self {
            config,
            handler: Arc::new(handler),
            guards,
            pool,
            active_connections: Arc::new(AtomicUsize::new(0)),
            listener: None,
        }
    }

    pub fn from_listener(listener: std::net::TcpListener, config: ServerConfig, handler: H) -> Self {
        let guards = build_guard_stack(&config.guards);
        let pool = ThreadPool::new(config.worker_threads);
        Self {
            config,
            handler: Arc::new(handler),
            guards,
            pool,
            active_connections: Arc::new(AtomicUsize::new(0)),
            listener: Some(listener),
        }
    }

    pub fn run(self) -> Result<(), SynError> {
        self.run_internal(None)
    }

    pub fn run_until_shutdown(self, shutdown: SyncShutdownSignal) -> Result<(), SynError> {
        self.run_internal(Some(shutdown))
    }

    fn run_internal(self, shutdown: Option<SyncShutdownSignal>) -> Result<(), SynError> {
        let listener = if let Some(l) = self.listener {
            l
        } else {
            std::net::TcpListener::bind(self.config.bind_addr)?
        };
        listener.set_nonblocking(shutdown.is_some())?;
        let actual_addr = listener.local_addr()?;
        info!("server {} listening on {}", self.config.name, actual_addr);

        loop {
            if let Some(signal) = shutdown.as_ref() {
                if signal.is_shutdown_requested() {
                    break;
                }
            }

            let (stream, peer_addr) = match listener.accept() {
                Ok(accepted) => accepted,
                Err(error)
                    if shutdown.is_some() && error.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    thread::sleep(Duration::from_millis(25));
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if let Err(error) = tcp::set_nodelay_sync(&stream, self.config.tcp_nodelay) {
                log::debug!("[{}] failed to set TCP_NODELAY: {}", peer_addr, error);
            }

            let active_connections = Arc::clone(&self.active_connections);
            let config = self.config.clone();
            let guards = self.guards.clone();
            let handler = Arc::clone(&self.handler);
            let active_connections_for_job = Arc::clone(&active_connections);

            let permit = active_connections.fetch_add(1, Ordering::SeqCst) + 1;
            if permit > config.max_connections {
                active_connections.fetch_sub(1, Ordering::SeqCst);
                log::warn!("[{}] dropping connection (max_connections reached)", peer_addr);
                continue;
            }

            let local_addr = stream.local_addr().ok();
            let is_tls_expected = config.tls.enabled || config.accept_mode == AcceptMode::Tls;
            let context = GuardContext::new(peer_addr, local_addr, is_tls_expected);

            if let Err(error) = self.pool.execute(Box::new(move || {
                let result = handle_sync_connection(stream, context, guards, config, handler);
                if let Err(error) = result {
                    log::error!("[{}] connection closed with error: {}", peer_addr, error);
                }

                active_connections_for_job.fetch_sub(1, Ordering::SeqCst);
            })) {
                active_connections.fetch_sub(1, Ordering::SeqCst);
                return Err(error);
            }
        }

        while self.active_connections.load(Ordering::SeqCst) > 0 {
            thread::sleep(Duration::from_millis(25));
        }

        Ok(())
    }
}

fn handle_sync_connection<H>(
    stream: std::net::TcpStream,
    context: GuardContext,
    guards: crate::guard::GuardStack,
    config: ServerConfig,
    handler: Arc<H>,
) -> Result<(), SynError>
where
    H: SyncConnectionHandler,
{
    // Enforce connection_timeout for I/O operations on this socket.
    let timeout = Some(config.connection_timeout);
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;

    let guard_session = guards.reserve(context.clone())?;

    let effective_mode = if config.accept_mode == AcceptMode::Mixed {
        AcceptMode::Mixed
    } else if config.tls.enabled || config.accept_mode == AcceptMode::Tls {
        AcceptMode::Tls
    } else {
        AcceptMode::Tcp
    };

    let connection = match effective_mode {
        AcceptMode::Tls => {
            #[cfg(any(feature = "rustls-backend", feature = "aws-lc-backend"))]
            {
                let tls_stream = tls::accept_sync(stream, &config.tls)?;
                let mut metadata = tcp::metadata(context.peer_addr, context.local_addr, true);
                metadata.tls_server_name = config.tls.server_name.clone();
                Connection::from_sync_server_tls(metadata, tls_stream)
            }
            #[cfg(not(any(feature = "rustls-backend", feature = "aws-lc-backend")))]
            return Err(SynError::UnsupportedFeature(
                "TLS requires the rustls-backend or aws-lc-backend feature",
            ));
        }
        AcceptMode::Mixed => {
            #[cfg(any(feature = "rustls-backend", feature = "aws-lc-backend"))]
            {
                if peek_is_tls(&stream)? {
                    let tls_stream = tls::accept_sync(stream, &config.tls)?;
                    let mut metadata = tcp::metadata(context.peer_addr, context.local_addr, true);
                    metadata.tls_server_name = config.tls.server_name.clone();
                    Connection::from_sync_server_tls(metadata, tls_stream)
                } else {
                    let metadata = tcp::metadata(context.peer_addr, context.local_addr, false);
                    Connection::from_sync_tcp(metadata, stream)
                }
            }
            #[cfg(not(any(feature = "rustls-backend", feature = "aws-lc-backend")))]
            return Err(SynError::UnsupportedFeature(
                "Mixed mode requires the rustls-backend or aws-lc-backend feature",
            ));
        }
        AcceptMode::Tcp => {
            let metadata = tcp::metadata(context.peer_addr, context.local_addr, false);
            Connection::from_sync_tcp(metadata, stream)
        }
    };

    guard_session.mark_established()?;
    let connection = attach_guard_session(connection, guard_session);

    handler.handle(connection)
}

#[cfg(any(feature = "rustls-backend", feature = "aws-lc-backend"))]
fn peek_is_tls(stream: &std::net::TcpStream) -> Result<bool, SynError> {
    let mut buf = [0u8; 1];
    match stream.peek(&mut buf) {
        Ok(1) => Ok(buf[0] == 0x16),
        Ok(_) => Ok(false),
        Err(e) => Err(e.into()),
    }
}