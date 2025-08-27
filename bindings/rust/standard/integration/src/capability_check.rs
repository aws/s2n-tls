// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{future::Future, panic::AssertUnwindSafe};

/// The libcrypto that s2n-tls is linked against.
#[derive(Debug, PartialEq, Eq)]
enum Libcrypto {
    Awslc,
    AwslcFips,
    OpenSsl102,
    OpenSsl111,
    OpenSsl30,
}

impl Libcrypto {
    /// Retrieve the libcrypto from the `S2N_LIBCRYPTO` env variable if available,
    /// otherwise return "awslc".
    ///
    /// S2N_LIBCRYPTO is set in CI as well as the Nix devshell.
    fn from_env() -> Self {
        let libcrypto = match std::env::var("S2N_LIBCRYPTO") {
            Ok(libcrypto) => libcrypto,
            Err(_) => {
                println!("S2N_LIBCRYPTO not set, assuming awslc");
                "awslc".to_string()
            }
        };

        match libcrypto.as_str() {
            "awslc" => Libcrypto::Awslc,
            "awslc-fips" => Libcrypto::AwslcFips,
            "openssl-1.0.2" => Libcrypto::OpenSsl102,
            "openssl-1.1.1" => Libcrypto::OpenSsl111,
            "openssl-3.0" => Libcrypto::OpenSsl30,
            _ => panic!("unexpected libcrypto: {libcrypto}"),
        }
    }
}

/// A `Capability` represents a functionality of s2n-tls that may or may not be
/// available depending on the linked libcrypto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Support for TLS 1.3
    Tls13,
    /// Support for ML-DSA and ML-KEM
    PQAlgorithms,
}

impl Capability {
    /// Returns whether a capability is supported.
    ///
    /// Internally, this just maps from the libcrypto to its supported capabilities.
    fn supported(&self) -> bool {
        let libcrypto = Libcrypto::from_env();
        match self {
            // OpenSSL 1.0.2 doesn't support RSA-PSS, so TLS 1.3 isn't enabled
            Capability::Tls13 => libcrypto != Libcrypto::OpenSsl102,
            // PQ is only supported for AWS-LC
            Capability::PQAlgorithms => {
                libcrypto == Libcrypto::Awslc || libcrypto == Libcrypto::AwslcFips
            }
        }
    }
}

/// Declare the required capabilities for a test to run.
///
/// If all the required capabilities are present then the test must pass. Otherwise
/// we expect the test to panic/fail.
pub fn required_capability(required_capabilities: &[Capability], test: fn()) {
    let result = std::panic::catch_unwind(test);
    if required_capabilities.iter().all(|c| c.supported()) {
        result.unwrap();
    } else {
        println!("expecting test failure");
        let panic = result.unwrap_err();
        println!("panic was {panic:?}");
    }
}

pub fn required_capability_async(
    required_capabilities: &[Capability],
    test: impl Future<Output = Result<(), Box<dyn std::error::Error>>>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| rt.block_on(test)));

    if required_capabilities.iter().all(Capability::supported) {
        // 1 -> no panic
        // 2 -> returned "ok"
        result.unwrap().unwrap();
    } else {
        println!("expecting test failure");
        match result {
            Ok(Ok(())) => panic!("test did not fail"),
            Ok(Err(e)) => println!("err was {e:?}"),
            Err(e) => println!("panic was {e:?}"),
        }
    }
}
