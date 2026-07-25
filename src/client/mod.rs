#[cfg(feature = "async")]
pub mod async_client;
#[cfg(feature = "sync")]
pub mod sync_client;
pub mod tcp;
pub mod tls;

#[cfg(feature = "async")]
pub use async_client::AsyncClient;

#[cfg(feature = "sync")]
pub use sync_client::SyncClient;