use std::{fs, sync::Arc};

use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls_pemfile as pemfile;

use crate::{config::{PemSource, TlsConfig}, SynError};

pub fn backend_name() -> &'static str {
    "rustls"
}

fn read_source(source: &PemSource) -> Result<Vec<u8>, SynError> {
    match source {
        PemSource::File { path } => Ok(fs::read(path)?),
        PemSource::Inline { pem } => Ok(pem.as_bytes().to_vec()),
    }
}

pub fn load_certs(source: &PemSource) -> Result<Vec<CertificateDer<'static>>, SynError> {
    let bytes = read_source(source)?;
    let mut cursor = &bytes[..];
    let certs = pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(SynError::from)?;
    Ok(certs)
}

pub fn load_private_key(source: &PemSource) -> Result<PrivateKeyDer<'static>, SynError> {
    let bytes = read_source(source)?;
    let mut cursor = &bytes[..];
    let key = pemfile::private_key(&mut cursor)
        .map_err(SynError::from)?
        .ok_or_else(|| SynError::config("no private key found in PEM source"))?;

    Ok(key)
}

fn build_root_store(sources: &[PemSource]) -> Result<Arc<RootCertStore>, SynError> {
    let mut roots = RootCertStore::empty();
    for source in sources {
        for cert in load_certs(source)? {
            roots.add(cert)?;
        }
    }

    Ok(Arc::new(roots))
}

pub fn build_server_config(tls: &TlsConfig) -> Result<Arc<ServerConfig>, SynError> {
    let certs = tls
        .certificate_chain
        .as_ref()
        .ok_or_else(|| SynError::config("server TLS is enabled but no certificate chain was provided"))
        .and_then(load_certs)?;
    let key = tls
        .private_key
        .as_ref()
        .ok_or_else(|| SynError::config("server TLS is enabled but no private key was provided"))
        .and_then(load_private_key)?;

    let builder = if tls.require_client_auth {
        let roots = build_root_store(&tls.trust_anchors)?;
        let verifier = rustls::server::WebPkiClientVerifier::builder(roots)
            .build()
            .map_err(|error| SynError::tls(error.to_string()))?;
        ServerConfig::builder().with_client_cert_verifier(verifier)
    } else if tls.trust_anchors.is_empty() {
        ServerConfig::builder().with_no_client_auth()
    } else {
        let roots = build_root_store(&tls.trust_anchors)?;
        let verifier = rustls::server::WebPkiClientVerifier::builder(roots)
            .allow_unauthenticated()
            .build()
            .map_err(|error| SynError::tls(error.to_string()))?;
        ServerConfig::builder().with_client_cert_verifier(verifier)
    };

    let mut config = builder.with_single_cert(certs, key)?;

    config.alpn_protocols = tls
        .alpn_protocols
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();

    Ok(Arc::new(config))
}

pub fn build_client_config(tls: &TlsConfig) -> Result<Arc<ClientConfig>, SynError> {
    let roots = build_root_store(&tls.trust_anchors)?;

    let mut config = if let (Some(cert_chain), Some(private_key)) = (
        tls.client_certificate_chain.as_ref(),
        tls.client_private_key.as_ref(),
    ) {
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(load_certs(cert_chain)?, load_private_key(private_key)?)?
    } else {
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    config.alpn_protocols = tls
        .alpn_protocols
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();

    Ok(Arc::new(config))
}

pub fn async_server_acceptor(tls: &TlsConfig) -> Result<tokio_rustls::TlsAcceptor, SynError> {
    Ok(tokio_rustls::TlsAcceptor::from(build_server_config(tls)?))
}

pub fn async_client_connector(tls: &TlsConfig) -> Result<tokio_rustls::TlsConnector, SynError> {
    Ok(tokio_rustls::TlsConnector::from(build_client_config(tls)?))
}

pub fn server_name(tls: &TlsConfig) -> Result<ServerName<'static>, SynError> {
    let name = tls.server_name.as_deref().unwrap_or("localhost");
    Ok(ServerName::try_from(name.to_owned()).map_err(|error| SynError::tls(error.to_string()))?)
}