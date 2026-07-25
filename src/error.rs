use std::{io, net::AddrParseError, time::Duration};

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SynError>;

#[derive(Debug, Error)]
pub enum SynError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("tls error: {0}")]
    Tls(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("address parse error: {0}")]
    AddrParse(#[from] AddrParseError),

    #[error("timeout after {after:?} while {context}")]
    Timeout { after: Duration, context: &'static str },

    #[error("rate limited: {scope} for {key}")]
    RateLimited { scope: &'static str, key: String },

    #[error("connection throttled: {scope} limit {limit}")]
    Throttled { scope: &'static str, limit: usize },

    #[error("ip banned: {0}")]
    BannedIp(String),

    #[error("guard {guard} rejected connection: {reason}")]
    GuardRejected { guard: &'static str, reason: String },

    #[error("malformed probe: {0}")]
    MalformedProbe(String),

    #[error("unsupported feature: {0}")]
    UnsupportedFeature(&'static str),

    #[error("runtime error: {0}")]
    Runtime(String),
}

impl SynError {
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub fn tls(message: impl Into<String>) -> Self {
        Self::Tls(message.into())
    }

    pub fn runtime(message: impl Into<String>) -> Self {
        Self::Runtime(message.into())
    }

    pub fn guard_rejected(guard: &'static str, reason: impl Into<String>) -> Self {
        Self::GuardRejected {
            guard,
            reason: reason.into(),
        }
    }

    pub fn rate_limited(scope: &'static str, key: impl Into<String>) -> Self {
        Self::RateLimited {
            scope,
            key: key.into(),
        }
    }

    pub fn throttled(scope: &'static str, limit: usize) -> Self {
        Self::Throttled { scope, limit }
    }

    pub fn timeout(after: Duration, context: &'static str) -> Self {
        Self::Timeout { after, context }
    }

    pub fn malformed_probe(message: impl Into<String>) -> Self {
        Self::MalformedProbe(message.into())
    }

    pub fn authentication_error(message: impl Into<String>) -> Self {
        Self::Config(format!("authentication error: {}", message.into()))
    }

    pub fn connection_error(message: impl Into<String>) -> Self {
        Self::Runtime(message.into())
    }
}

#[cfg(any(feature = "rustls-backend", feature = "aws-lc-backend"))]
impl From<rustls::Error> for SynError {
    fn from(error: rustls::Error) -> Self {
        Self::tls(error.to_string())
    }
}

#[cfg(feature = "async")]
impl From<tokio::task::JoinError> for SynError {
    fn from(error: tokio::task::JoinError) -> Self {
        Self::runtime(error.to_string())
    }
}