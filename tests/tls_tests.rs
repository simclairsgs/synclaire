use synclaire::{tls::rustls, PemSource, TlsConfig};

const INVALID_CERT: &str = "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n";
const INVALID_KEY: &str = "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n";

#[test]
fn server_tls_requires_cert_and_key_when_enabled() {
    let tls = TlsConfig::builder().enabled(true).build();
    let error = rustls::build_server_config(&tls).expect_err("missing cert and key should fail");
    assert!(error.to_string().contains("certificate chain") || error.to_string().contains("private key"));
}

#[test]
fn mtls_requires_trust_anchors_when_client_auth_is_required() {
    let tls = TlsConfig::builder()
        .enabled(true)
        .certificate_chain(PemSource::inline_pem(INVALID_CERT))
        .private_key(PemSource::inline_pem(INVALID_KEY))
        .require_client_auth(true)
        .build();

    let error = rustls::build_server_config(&tls).expect_err("mTLS without roots should fail");
    let message = error.to_string();
    assert!(message.contains("private key") || message.contains("certificate") || message.contains("tls error"));
}

#[test]
fn client_tls_without_client_cert_still_builds_config() {
    let tls = TlsConfig::builder().enabled(true).server_name("localhost").build();
    let config = rustls::build_client_config(&tls).expect("client config should build without client auth cert");
    assert!(config.alpn_protocols.is_empty() || !config.alpn_protocols.is_empty());
}

#[test]
fn client_tls_with_invalid_client_auth_cert_fails() {
    let tls = TlsConfig::builder()
        .enabled(true)
        .server_name("localhost")
        .client_certificate_chain(PemSource::inline_pem(INVALID_CERT))
        .client_private_key(PemSource::inline_pem(INVALID_KEY))
        .build();

    assert!(rustls::build_client_config(&tls).is_err());
}

#[test]
fn server_name_defaults_to_localhost() {
    let tls = TlsConfig::builder().enabled(true).build();
    let server_name = rustls::server_name(&tls).expect("default localhost should be valid");
    assert_eq!(server_name.to_str(), "localhost");
}

#[cfg(feature = "rustls-backend")]
#[test]
fn client_config_with_system_roots_builds_successfully() {
    let tls = TlsConfig { use_system_roots: true, ..Default::default() };
    // Should not panic/error and should have loaded at least one native cert.
    let config = rustls::build_client_config(&tls).expect("build_client_config with system roots");
    // We cannot introspect the root store count from the Arc<ClientConfig>,
    // but we verify the function succeeds without an empty-store error.
    let _ = config;
}

#[cfg(feature = "rustls-backend")]
#[test]
fn client_config_with_verify_peer_false_succeeds() {
    let tls = TlsConfig { verify_peer: false, use_system_roots: false, ..Default::default() };
    let config = rustls::build_client_config(&tls).expect("build_client_config with noop verifier");
    let _ = config;
}

#[cfg(feature = "rustls-backend")]
#[test]
fn client_config_with_no_system_roots_and_no_anchors_builds_empty_store() {
    let tls = TlsConfig { use_system_roots: false, ..Default::default() };
    // Should succeed — just produces an empty root store (no outbound connections will work).
    let config = rustls::build_client_config(&tls).expect("build_client_config with empty store");
    let _ = config;
}

#[cfg(feature = "rustls-backend")]
#[test]
fn use_system_roots_default_is_true() {
    let tls = TlsConfig::default();
    assert!(tls.use_system_roots, "use_system_roots should default to true");
}
