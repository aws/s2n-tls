// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod harness;
#[cfg(feature = "openssl")]
pub mod openssl;
#[cfg(feature = "rustls")]
pub mod rustls;
pub mod s2n_tls;

#[cfg(feature = "openssl")]
pub use crate::openssl::OpenSslHarness;
#[cfg(feature = "rustls")]
pub use crate::rustls::RustlsHarness;
pub use crate::{
    harness::{CipherSuite, CryptoConfig, ECGroup, HandshakeType, Mode, SigType, TlsBenchHarness},
    s2n_tls::S2NHarness,
};

#[derive(Clone, Copy)]
pub enum PemType {
    ServerKey,
    ServerCertChain,
    ClientKey,
    ClientCertChain,
    CACert,
}

impl PemType {
    fn get_filename(&self) -> &str {
        match self {
            PemType::ServerKey => "server-key.pem",
            PemType::ServerCertChain => "server-cert.pem",
            PemType::ClientKey => "client-key.pem",
            PemType::ClientCertChain => "client-cert.pem",
            PemType::CACert => "ca-cert.pem",
        }
    }
}

fn get_cert_path(pem_type: PemType, sig_type: SigType) -> String {
    format!(
        "certs/{}/{}",
        sig_type.get_dir_name(),
        pem_type.get_filename()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use PemType::*;
    use SigType::*;

    #[test]
    fn cert_paths_valid() {
        for pem_type in [
            ServerKey,
            ServerCertChain,
            ClientKey,
            ClientCertChain,
            CACert,
        ] {
            for sig_type in [Rsa2048, Rsa3072, Rsa4096, Ec384] {
                assert!(
                    Path::new(&get_cert_path(pem_type, sig_type)).exists(),
                    "cert not found"
                );
            }
        }
    }
}
