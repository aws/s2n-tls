// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod harness;
pub mod openssl;
pub mod rustls;
pub mod s2n_tls;
pub use crate::{
    harness::{CipherSuite, CryptoConfig, ECGroup, SigType, TlsBenchHarness},
    openssl::OpenSslHarness,
    rustls::RustlsHarness,
    s2n_tls::S2NHarness,
};

pub enum PemType {
    ServerKey,
    ServerCertChain,
    ClientKey,
    ClientCertChain,
    CACert,
}

use PemType::*;
use SigType::*;

fn get_cert_path(pem_type: &PemType, sig_type: &SigType) -> String {
    let filename = match pem_type {
        ServerKey => "server-key.pem",
        ServerCertChain => "server-fullchain.pem",
        ClientKey => "client-key.pem",
        ClientCertChain => "client-fullchain.pem",
        CACert => "ca-cert.pem",
    };

    let dir = match sig_type {
        Rsa2048 => "rsa2048",
        Rsa4096 => "rsa4096",
        Ec384 => "ec384",
    };

    format!("certs/{dir}/{filename}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn cert_paths_valid() {
        for pem_type in [
            ServerKey,
            ServerCertChain,
            ClientKey,
            ClientCertChain,
            CACert,
        ] {
            for sig_type in [Rsa2048, Rsa4096, Ec384] {
                assert!(Path::new(&get_cert_path(&pem_type, &sig_type)).exists());
            }
        }
    }
}
