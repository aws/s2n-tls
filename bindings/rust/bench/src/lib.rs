pub mod harness;
pub mod s2n_tls;
pub use crate::{harness::TlsImpl, s2n_tls::S2nTls};
pub use harness::read_to_bytes;

const SERVER_KEY_PATH: &str = "src/certs/server-key.pem";
const SERVER_CERT_CHAIN_PATH: &str = "src/certs/fullchain.pem";
const CA_CERT_PATH: &str = "src/certs/ca-cert.pem";
