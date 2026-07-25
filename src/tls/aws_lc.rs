// AWS LC backend — not yet implemented.
// This module is reserved for a future FIPS-compliant backend using aws-lc-rs.
// Currently, all TLS operations use the rustls-backend (ring provider).

pub fn backend_name() -> &'static str {
    "aws-lc-rs (not yet implemented)"
}
