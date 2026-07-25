use std::{fs, sync::Arc};

use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use rustls_pemfile as pemfile;

use crate::{config::{PemSource, TlsConfig}, SynError};

/// Certificate verifier that accepts any server certificate.
///
/// Used only when `TlsConfig::verify_peer = false`.
///
/// **Security:** This disables all certificate validation and makes the connection
/// vulnerable to man-in-the-middle attacks. Use only in controlled environments.
#[derive(Debug)]
struct NoopServerVerifier;

impl ServerCertVerifier for NoopServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // The noop verifier must accept every scheme a real server might use.
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

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
    let roots = build_root_store_for_client(tls)?;
    let builder = ClientConfig::builder().with_root_certificates(roots);

    let mut config = if !tls.verify_peer {
        // Caller has disabled peer verification; install the no-op verifier.
        let mut cfg = if let (Some(cert_chain), Some(private_key)) = (
            tls.client_certificate_chain.as_ref(),
            tls.client_private_key.as_ref(),
        ) {
            builder.with_client_auth_cert(load_certs(cert_chain)?, load_private_key(private_key)?)?
        } else {
            builder.with_no_client_auth()
        };
        cfg.dangerous().set_certificate_verifier(Arc::new(NoopServerVerifier));
        cfg
    } else if let (Some(cert_chain), Some(private_key)) = (
        tls.client_certificate_chain.as_ref(),
        tls.client_private_key.as_ref(),
    ) {
        builder.with_client_auth_cert(load_certs(cert_chain)?, load_private_key(private_key)?)?
    } else {
        builder.with_no_client_auth()
    };

    config.alpn_protocols = tls
        .alpn_protocols
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();

    Ok(Arc::new(config))
}

fn build_root_store_for_client(tls: &TlsConfig) -> Result<Arc<RootCertStore>, SynError> {
    if !tls.trust_anchors.is_empty() {
        return build_root_store(&tls.trust_anchors);
    }
    if tls.use_system_roots {
        let mut roots = RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs();
        // Log warnings for unreadable certs but continue with what was loaded.
        for err in &native_certs.errors {
            log::warn!("native cert load warning: {}", err);
        }
        for cert in native_certs.certs {
            if let Err(e) = roots.add(cert) {
                log::warn!("skipping invalid native cert: {}", e);
            }
        }
        return Ok(Arc::new(roots));
    }
    // Explicit empty store — caller requested no roots.
    Ok(Arc::new(RootCertStore::empty()))
}

#[cfg(feature = "async")]
pub fn async_server_acceptor(tls: &TlsConfig) -> Result<tokio_rustls::TlsAcceptor, SynError> {
    Ok(tokio_rustls::TlsAcceptor::from(build_server_config(tls)?))
}

#[cfg(feature = "async")]
pub fn async_client_connector(tls: &TlsConfig) -> Result<tokio_rustls::TlsConnector, SynError> {
    Ok(tokio_rustls::TlsConnector::from(build_client_config(tls)?))
}

pub fn server_name(tls: &TlsConfig) -> Result<ServerName<'static>, SynError> {
    let name = tls.server_name.as_deref().unwrap_or("localhost");
    ServerName::try_from(name.to_owned()).map_err(|error| SynError::tls(error.to_string()))
}
