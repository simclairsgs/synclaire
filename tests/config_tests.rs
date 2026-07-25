use std::time::Duration;

use synclaire::{ClientConfig, PemSource, ServerConfig, TlsConfig};

#[test]
fn server_defaults_are_sensible() {
    let config = ServerConfig::default();
    assert_eq!(config.bind_addr.to_string(), "127.0.0.1:7000");
    assert!(config.max_connections > 0);
    assert_eq!(config.connection_timeout, Duration::from_secs(30));
    assert!(!config.tls.enabled);
}

#[test]
fn client_defaults_are_sensible() {
    let config = ClientConfig::default();
    assert_eq!(config.connect_addr.to_string(), "127.0.0.1:7000");
    assert_eq!(config.connection_timeout, Duration::from_secs(10));
    assert!(!config.tls.enabled);
}

#[test]
fn tls_builder_supports_mtls_fields() {
    let tls = TlsConfig::builder()
        .enabled(true)
        .server_name("example.com")
        .certificate_chain(PemSource::inline_pem("server-cert"))
        .private_key(PemSource::inline_pem("server-key"))
        .client_certificate_chain(PemSource::inline_pem("client-cert"))
        .client_private_key(PemSource::inline_pem("client-key"))
        .require_client_auth(true)
        .verify_peer(true)
        .build();

    assert!(tls.enabled);
    assert_eq!(tls.server_name.as_deref(), Some("example.com"));
    assert!(tls.client_certificate_chain.is_some());
    assert!(tls.client_private_key.is_some());
    assert!(tls.require_client_auth);
}

#[test]
fn pem_source_from_bytes_roundtrips_text() {
    let source = PemSource::from_pem_bytes(b"-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n");
    match source {
        PemSource::Inline { pem } => assert!(pem.contains("BEGIN CERTIFICATE")),
        PemSource::File { .. } => panic!("expected inline pem"),
    }
}

#[test]
fn server_and_client_builder_configuration_works() {
    let server = ServerConfig::builder()
        .bind_addr("127.0.0.1:7100".parse().expect("valid socket address"))
        .worker_threads(2)
        .connection_timeout(Duration::from_secs(20))
        .max_connections(128)
        .tcp_nodelay(true)
        .name("server-builder")
        .build();

    assert_eq!(server.bind_addr.to_string(), "127.0.0.1:7100");
    assert_eq!(server.max_connections, 128);
    assert_eq!(server.name, "server-builder");

    let client = ClientConfig::builder()
        .connect_addr("127.0.0.1:7100".parse().expect("valid socket address"))
        .connection_timeout(Duration::from_secs(5))
        .tcp_nodelay(true)
        .name("client-builder")
        .build();

    assert_eq!(client.connect_addr.to_string(), "127.0.0.1:7100");
    assert_eq!(client.name, "client-builder");
}