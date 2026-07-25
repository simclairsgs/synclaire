#[cfg(feature = "aws-lc-backend")]
use aws_lc_rs as _;

pub fn backend_name() -> &'static str {
    "aws-lc-rs"
}

pub fn describe_backend() -> &'static str {
    "aws-lc-rs backend is available behind the aws-lc-backend feature"
}