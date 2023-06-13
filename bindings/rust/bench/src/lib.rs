pub mod harness;
pub mod openssl;
pub mod rustls;
pub mod s2n_tls;
pub use crate::{harness::TlsImpl, openssl::OpenSsl, rustls::Rustls, s2n_tls::S2nTls};
pub use harness::read_to_bytes;

const SERVER_KEY_PATH: &str = "src/certs/server-key.pem";
const SERVER_CERT_CHAIN_PATH: &str = "src/certs/fullchain.pem";
const CA_CERT_PATH: &str = "src/certs/ca-cert.pem";
