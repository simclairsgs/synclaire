use std::sync::Arc;

use tokio::{
    net::TcpListener,
    sync::{watch, Semaphore},
};
use log::info;

use crate::{
    config::{AcceptMode, ServerConfig},
    guard::GuardContext,
    handler::{attach_guard_session, AsyncStream, Connection, ConnectionHandler},
    server::{build_guard_stack, tcp, tls},
    SynError,
};

#[derive(Clone, Debug)]
pub struct AsyncServerShutdown {
    sender: watch::Sender<bool>,
}

impl AsyncServerShutdown {
    pub fn shutdown(&self) -> Result<(), SynError> {
        self.sender
            .send(true)
            .map_err(|_| SynError::runtime("async shutdown signal failed"))
    }
}

pub struct AsyncServer<H> {
    config: ServerConfig,
    handler: Arc<H>,
    guards: crate::guard::GuardStack,
}

impl<H> AsyncServer<H>
where
    H: ConnectionHandler,
{
    pub fn shutdown_channel() -> (AsyncServerShutdown, watch::Receiver<bool>) {
        let (sender, receiver) = watch::channel(false);
        (AsyncServerShutdown { sender }, receiver)
    }

    pub fn new(config: ServerConfig, handler: H) -> Self {
        let guards = build_guard_stack(&config.guards);
        Self {
            config,
            handler: Arc::new(handler),
            guards,
        }
    }

    pub async fn run(self) -> Result<(), SynError> {
        self.run_internal(None).await
    }

    pub async fn run_until_shutdown(self, shutdown: watch::Receiver<bool>) -> Result<(), SynError> {
        self.run_internal(Some(shutdown)).await
    }

    async fn run_internal(self, mut shutdown: Option<watch::Receiver<bool>>) -> Result<(), SynError> {
        let listener = TcpListener::bind(self.config.bind_addr).await?;
        info!("server {} listening on {}", self.config.name, self.config.bind_addr);

        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));

        loop {
            let (stream, peer_addr) = if let Some(signal) = shutdown.as_mut() {
                tokio::select! {
                    accepted = listener.accept() => accepted?,
                    signal_result = signal.changed() => {
                        if signal_result.is_err() || *signal.borrow() {
                            break;
                        }
                        continue;
                    }
                }
            } else {
                listener.accept().await?
            };
            if let Err(error) = tcp::set_nodelay_async(&stream, self.config.tcp_nodelay).await {
                log::debug!("[{}] failed to set TCP_NODELAY: {}", peer_addr, error);
            }

            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    log::warn!("[{}] dropping connection (max_connections reached)", peer_addr);
                    continue;
                }
            };

            let local_addr = stream.local_addr().ok();
            let is_tls_expected = self.config.tls.enabled || self.config.accept_mode == AcceptMode::Tls;
            let context = GuardContext::new(peer_addr, local_addr, is_tls_expected);
            let guard_session = match self.guards.reserve(context.clone()) {
                Ok(session) => session,
                Err(error) => {
                    log::warn!("[{}] guard rejected connection: {}", peer_addr, error);
                    drop(permit);
                    continue;
                }
            };

            let handler = Arc::clone(&self.handler);
            let config = self.config.clone();

            tokio::spawn(async move {
                let result = handle_async_connection(stream, context, guard_session, config, handler).await;
                if let Err(error) = result {
                    log::error!("[{}] connection closed with error: {}", peer_addr, error);
                }
                drop(permit);
            });
        }

        // Wait for all active connection tasks to release their permits.
        let max_permits = u32::try_from(self.config.max_connections)
            .map_err(|_| SynError::runtime("max_connections exceeds async shutdown limit"))?;
        let all_permits = semaphore
            .acquire_many(max_permits)
            .await
            .map_err(|_| SynError::runtime("semaphore closed during async shutdown"))?;
        drop(all_permits);

        Ok(())
    }
}

async fn handle_async_connection<H>(
    stream: tokio::net::TcpStream,
    context: GuardContext,
    guard_session: crate::guard::GuardSession,
    config: ServerConfig,
    handler: Arc<H>,
) -> Result<(), SynError>
where
    H: ConnectionHandler,
{
    // Backward compat: treat tls.enabled == true as AcceptMode::Tls
    let effective_mode = if config.accept_mode == AcceptMode::Mixed {
        AcceptMode::Mixed
    } else if config.tls.enabled || config.accept_mode == AcceptMode::Tls {
        AcceptMode::Tls
    } else {
        AcceptMode::Tcp
    };

    let (async_stream, is_tls) = match effective_mode {
        AcceptMode::Tls => {
            let s = tls::accept_async(stream, &config.tls).await?;
            (AsyncStream::ServerTls(s), true)
        }
        AcceptMode::Mixed => {
            // TLS ClientHello record type byte is 0x16
            // TODO: benchmark whether a one-byte peek adds measurable latency
            if peek_is_tls(&stream).await {
                let s = tls::accept_async(stream, &config.tls).await?;
                (AsyncStream::ServerTls(s), true)
            } else {
                (AsyncStream::Tcp(stream), false)
            }
        }
        AcceptMode::Tcp => (AsyncStream::Tcp(stream), false),
    };

    let mut metadata = tcp::metadata(context.peer_addr, context.local_addr, is_tls);
    if is_tls {
        metadata.tls_server_name = config.tls.server_name.clone();
    }

    let connection = Connection::from_async_stream(metadata, async_stream);
    guard_session.mark_established()?;
    let connection = attach_guard_session(connection, guard_session);

    let timeout = config.connection_timeout;
    match tokio::time::timeout(timeout, handler.handle(connection)).await {
        Ok(result) => result,
        Err(_) => {
            log::debug!("[{}] connection timed out after {:?}", context.peer_addr, timeout);
            Ok(())
        }
    }
}

/// Peek at the first byte to decide if this is a TLS ClientHello.
/// Returns `true` when the byte is 0x16 (TLS Handshake record type).
async fn peek_is_tls(stream: &tokio::net::TcpStream) -> bool {
    let mut buf = [0u8; 1];
    matches!(stream.peek(&mut buf).await, Ok(1) if buf[0] == 0x16)
}
