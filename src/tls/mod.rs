pub mod aws_lc;
#[cfg(feature = "rustls-backend")]
pub mod rustls;

#[cfg(feature = "rustls-backend")]
pub use rustls::{build_client_config, build_server_config, load_certs, load_private_key, server_name};
#[cfg(all(feature = "rustls-backend", feature = "async"))]
pub use rustls::{async_client_connector, async_server_acceptor};

pub enum Backend {
    Rustls,
    AwsLc,
}

pub fn selected_backend(prefer_aws_lc: bool) -> Backend {
    if prefer_aws_lc && cfg!(feature = "aws-lc-backend") {
        Backend::AwsLc
    } else {
        Backend::Rustls
    }
}