// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::LazyLock;

/// the `pems` folder storing most of the s2n-tls unit test certs
const TEST_PEMS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../tests/pems/");

pub static ML_DSA_87: LazyLock<CertMaterials> = LazyLock::new(|| CertMaterials {
    server_key_path: format!("{TEST_PEMS_PATH}mldsa/ML-DSA-87-seed.priv"),
    server_chain_path: format!("{TEST_PEMS_PATH}mldsa/ML-DSA-87.crt"),
    client_key_path: None,
    client_chain_path: None,
    ca_path: format!("{TEST_PEMS_PATH}mldsa/ML-DSA-87.crt"),
});

pub static ML_DSA_44: LazyLock<CertMaterials> = LazyLock::new(|| CertMaterials {
    server_key_path: format!("{TEST_PEMS_PATH}mldsa/ML-DSA-44-seed.priv"),
    server_chain_path: format!("{TEST_PEMS_PATH}mldsa/ML-DSA-44.crt"),
    client_key_path: None,
    client_chain_path: None,
    ca_path: format!("{TEST_PEMS_PATH}mldsa/ML-DSA-44.crt"),
});

/// A self-signed cert with a CN of `beaver`
pub static BEAVER: LazyLock<CertMaterials> = LazyLock::new(|| CertMaterials {
    server_key_path: format!("{TEST_PEMS_PATH}sni/beaver_key.pem"),
    server_chain_path: format!("{TEST_PEMS_PATH}sni/beaver_cert.pem"),
    client_key_path: None,
    client_chain_path: None,
    ca_path: format!("{TEST_PEMS_PATH}sni/beaver_cert.pem"),
});

/// CertMaterials holds the paths to PEM-formatted files
#[derive(Debug, Clone)]
pub struct CertMaterials {
    pub server_key_path: String,
    pub server_chain_path: String,
    pub client_key_path: Option<String>,
    pub client_chain_path: Option<String>,
    /// This will either be set to the specific CA, or may be set to the server_chain
    /// patch in the case of a self signed cert
    /// path in the case of a self signed cert
    pub ca_path: String,
}

impl CertMaterials {
    /// return the cert materials from a "permutation" in test/pems/
    pub fn from_permutation(permutation: &str) -> Self {
        let folder = format!("{TEST_PEMS_PATH}permutations/{permutation}");
        CertMaterials {
            server_key_path: format!("{folder}/server-key.pem"),
            server_chain_path: format!("{folder}/server-chain.pem"),
            client_key_path: Some(format!("{folder}/client-key.pem")),
            client_chain_path: Some(format!("{folder}/client-cert.pem")),
            ca_path: format!("{folder}/ca-cert.pem"),
        }
    }

    pub fn server_chain(&self) -> Vec<u8> {
        std::fs::read(&self.server_chain_path).unwrap()
    }

    pub fn server_key(&self) -> Vec<u8> {
        std::fs::read(&self.server_key_path).unwrap()
    }

    pub fn ca(&self) -> Vec<u8> {
        std::fs::read(&self.ca_path).unwrap()
    }
}
