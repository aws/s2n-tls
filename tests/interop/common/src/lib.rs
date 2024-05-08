// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{env, fmt::Display, str::FromStr};

/// `Common` provides a crate with functionality that other TLS implementors
/// might find useful if they are implementing a rust shim.

/// This message is send to the server at the start of several test cases
pub const CLIENT_GREETING: &str = "i am the client. nice to meet you server.";
/// This short message is sent after the client greeting in the "request-response"
/// scenarios.
pub const SERVER_RESPONSE: &str = "i am the server. a pleasure to make your acquaintance.";
/// The amount of data that will be downloaded by the large download test. Note 
/// that the interop tests use a GB as 1_000^3 bytes, not 1_024^3 bytes
pub const LARGE_DATA_DOWNLOAD_GB: u64 = 256;
/// If a server or client doesn't support a test case, then the process should
/// exit with this value.
pub const UNIMPLEMENTED_RETURN_VAL: i32 = 127;

pub enum PemType {
    CaCert,
    ServerChain,
    ServerKey,
    ClientChain,
    ClientKey,
}

pub fn pem_directory() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/..",
        "/certificates/"
    )
}

pub fn pem_file_path(file: PemType) -> &'static str {
    match file {
        PemType::CaCert => concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/..",
            "/certificates/ca-cert.pem"
        ),
        PemType::ServerChain => concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/..",
            "/certificates/server-chain.pem"
        ),
        PemType::ServerKey => concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/..",
            "/certificates/server-key.pem"
        ),
        PemType::ClientChain => concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/..",
            "/certificates/client-cert.pem"
        ),
        PemType::ClientKey => concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/..",
            "/certificates/client-key.pem"
        ),
    }
}

/// This method is used to parse the server arguments from the command line argv.
///
/// It will the return the [InteropTest] that is being run, as well as the expected
/// port for the server to run on.
pub fn parse_server_arguments() -> (InteropTest, u16) {
    let args: Vec<String> = env::args().skip(1).collect();
    let test: InteropTest = args
        .first()
        .expect("you must supply command line arguments")
        .parse()
        .unwrap();
    let port = args[1].parse().unwrap();
    (test, port)
}

/// This enum contains all of the defined Interop Test types. See the readme for more
/// details.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum InteropTest {
    Handshake,
    RequestResponse,
    LargeDataDownload,
    LargeDataDownloadWithFrequentKeyUpdates,
    MTLSRequestResponse,
}

impl FromStr for InteropTest {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = match s {
            "handshake" => InteropTest::Handshake,
            "request_response" => InteropTest::RequestResponse,
            "large_data_download" => InteropTest::LargeDataDownload,
            "large_data_download_with_frequent_key_updates" => {
                InteropTest::LargeDataDownloadWithFrequentKeyUpdates
            }
            "mtls_request_response" => InteropTest::MTLSRequestResponse,
            _ => return Err(format!("unrecognized test type: {}", s)),
        };
        Ok(name)
    }
}

impl Display for InteropTest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            InteropTest::Handshake => "handshake",
            InteropTest::RequestResponse => "request_response",
            InteropTest::LargeDataDownload => "large_data_download",
            InteropTest::LargeDataDownloadWithFrequentKeyUpdates => {
                "large_data_download_with_frequent_key_updates"
            },
            InteropTest::MTLSRequestResponse => "mtls_request_response",
        };
        write!(f, "{}", name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_paths_valid() {
        std::fs::read(pem_file_path(PemType::CaCert)).unwrap();
        std::fs::read(pem_file_path(PemType::ServerChain)).unwrap();
        std::fs::read(pem_file_path(PemType::ServerKey)).unwrap();
        std::fs::read(pem_file_path(PemType::ClientChain)).unwrap();
        std::fs::read(pem_file_path(PemType::ClientKey)).unwrap();
    }
}
