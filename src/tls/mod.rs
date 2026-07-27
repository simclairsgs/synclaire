#[cfg(any(feature = "rustls-backend", feature = "aws-lc-backend"))]
pub mod rustls;

#[cfg(all(
    any(feature = "rustls-backend", feature = "aws-lc-backend"),
    feature = "async"
))]
pub use rustls::{async_client_connector, async_server_acceptor};
#[cfg(any(feature = "rustls-backend", feature = "aws-lc-backend"))]
pub use rustls::{
    build_client_config, build_server_config, load_certs, load_private_key, server_name,
};
