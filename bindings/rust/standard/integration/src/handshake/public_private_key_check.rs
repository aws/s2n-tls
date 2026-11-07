// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::utilities::certs::CertMaterials;
use s2n_tls::{cert_chain, config};

/// An RSA cert chain paired with an unrelated RSA private key (same key type,
/// different key).
fn rsa_cert_with_mismatched_rsa_key() -> (Vec<u8>, Vec<u8>) {
    let cert = CertMaterials::from_permutation("rsae_pkcs_2048_sha256");
    let other = CertMaterials::from_permutation("rsae_pkcs_4096_sha384");
    (cert.server_chain(), other.server_key())
}

/// An RSA cert chain paired with an ECDSA private key (different key type).
fn rsa_cert_with_mismatched_ecdsa_key() -> (Vec<u8>, Vec<u8>) {
    let cert = CertMaterials::from_permutation("rsae_pkcs_2048_sha256");
    let other = CertMaterials::from_permutation("ec_ecdsa_p384_sha384");
    (cert.server_chain(), other.server_key())
}

/// Loading a mismatched cert/key pair should succeed, because the public/private
/// key check is not enforced.
///
/// While s2n-tls previously enforced enforced these checks, it was tremendously
/// expensive for large multi-tenant customers, and caused significantly more pain
/// than it saved. If we ever wish to return to this behavior, we should carefully
/// consider the impact on large multi-tenant customers.
#[test]
fn config_load_pem_with_mismatched_key_succeeds() {
    for (chain, key) in [
        rsa_cert_with_mismatched_rsa_key(),
        rsa_cert_with_mismatched_ecdsa_key(),
    ] {
        // direct load
        let mut builder = config::Builder::new();
        builder.with_system_certs(false).unwrap();
        builder.load_pem(&chain, &key).unwrap();

        // cert chain creation
        let mut builder = cert_chain::Builder::new().unwrap();
        builder.load_pem(&chain, &key).unwrap();
        builder.build().unwrap();
    }
}
