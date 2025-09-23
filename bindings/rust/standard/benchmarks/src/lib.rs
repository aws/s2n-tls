// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module holds all of the "benchmark specific" configuration logic that is
//! used in the benchmark suites.
//!
//! Anything that is only relevant to the benchmarks should live in this module.
//! Similarly, anything that might be used outside of the benchmarks should _not_
//! live in this module.

use std::{error::Error, fmt::Debug};

mod setup;
#[cfg(test)]
mod test_utilities;

use tls_harness::{Mode, SigType, TlsConnPair, TlsConnection};

/// While ServerAuth and Resumption are not mutually exclusive, they are treated
/// as such for the purpose of benchmarking.
#[derive(Clone, Copy, Default, Eq, PartialEq, strum::EnumIter)]
pub enum HandshakeType {
    #[default]
    ServerAuth,
    MutualAuth,
    Resumption,
}

impl Debug for HandshakeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeType::ServerAuth => write!(f, "server-auth"),
            HandshakeType::MutualAuth => write!(f, "mTLS"),
            HandshakeType::Resumption => write!(f, "resumption"),
        }
    }
}

// these parameters were the only ones readily usable for all three libaries:
// s2n-tls, rustls, and openssl
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, strum::EnumIter)]
pub enum CipherSuite {
    #[default]
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
}

#[derive(Clone, Copy, Default, strum::EnumIter)]
pub enum KXGroup {
    Secp256R1,
    #[default]
    X25519,
}

impl Debug for KXGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secp256R1 => write!(f, "secp256r1"),
            Self::X25519 => write!(f, "x25519"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CryptoConfig {
    pub cipher_suite: CipherSuite,
    pub kx_group: KXGroup,
    pub sig_type: SigType,
}

impl CryptoConfig {
    pub fn new(cipher_suite: CipherSuite, kx_group: KXGroup, sig_type: SigType) -> Self {
        Self {
            cipher_suite,
            kx_group,
            sig_type,
        }
    }
}

/// The TlsBenchConfig trait allows us to map benchmarking parameters to
/// a configuration object
pub trait TlsBenchConfig: Sized {
    fn make_config(
        mode: Mode,
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>>;
}

/// Initialize buffers, configs, and connections (pre-handshake)
pub fn new_bench_pair<C, S>(
    crypto_config: CryptoConfig,
    handshake_type: HandshakeType,
) -> Result<TlsConnPair<C, S>, Box<dyn Error>>
where
    C: TlsConnection,
    S: TlsConnection,
    C::Config: TlsBenchConfig,
    S::Config: TlsBenchConfig,
{
    // do an initial handshake to generate the session ticket
    if handshake_type == HandshakeType::Resumption {
        let server_config = S::Config::make_config(Mode::Server, crypto_config, handshake_type)?;
        let client_config = C::Config::make_config(Mode::Client, crypto_config, handshake_type)?;

        // handshake the client and server connections. This will result in
        // session ticket getting stored in client_config
        let mut pair = TlsConnPair::<C, S>::from_configs(&client_config, &server_config);
        pair.handshake()?;
        // NewSessionTicket messages are part of the application data and sent
        // after the handshake is complete, so we must trigger an additional
        // "read" on the client connection to ensure that the session ticket
        // gets received and stored in the config
        pair.round_trip_transfer(&mut [0]).unwrap();
        // OpenSSL doesn't allow resumption unless the session was cleanly shutdown
        pair.shutdown().unwrap();

        // new_from_config is called interally by the TlsConnPair::new
        // method and will check if a session ticket is available and set it
        // on the connection. This results in the session ticket in
        // client_config (from the previous handshake) getting set on the
        // client connection.
        return Ok(TlsConnPair::<C, S>::from_configs(
            &client_config,
            &server_config,
        ));
    }

    Ok(TlsConnPair::<C, S>::from_configs(
        &C::Config::make_config(Mode::Client, crypto_config, handshake_type).unwrap(),
        &S::Config::make_config(Mode::Server, crypto_config, handshake_type).unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use tls_harness::{
        cohort::{OpenSslConnection, RustlsConnection, S2NConnection},
        harness::TlsInfo,
        TlsConnection,
    };

    #[test]
    fn rustls_handshakes() {
        test_utilities::all_handshakes::<RustlsConnection>();
    }

    #[test]
    fn openssl_handshakes() {
        test_utilities::all_handshakes::<OpenSslConnection>();
    }

    #[test]
    fn s2n_handshakes() {
        test_utilities::all_handshakes::<S2NConnection>();
    }

    #[test]
    fn rustls_transfer() {
        test_utilities::transfer::<RustlsConnection>();
    }

    #[test]
    fn openssl_transfer() {
        test_utilities::transfer::<OpenSslConnection>();
    }

    #[test]
    fn s2n_transfer() {
        test_utilities::transfer::<S2NConnection>();
    }

    fn session_resumption<C, S>()
    where
        S: TlsConnection + TlsInfo,
        C: TlsConnection + TlsInfo,
        C::Config: TlsBenchConfig,
        S::Config: TlsBenchConfig,
    {
        println!("testing with client:{} server:{}", C::name(), S::name());
        let mut conn_pair =
            new_bench_pair::<C, S>(CryptoConfig::default(), HandshakeType::Resumption).unwrap();
        conn_pair.handshake().unwrap();
        // read the session tickets which were sent
        let err = conn_pair.client_mut().recv(&mut [0]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);

        assert!(conn_pair.server().resumed_connection());
        conn_pair.shutdown().unwrap();
    }

    #[test]
    fn session_resumption_interop() {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init()
            .unwrap();
        session_resumption::<S2NConnection, S2NConnection>();
        session_resumption::<S2NConnection, RustlsConnection>();
        session_resumption::<S2NConnection, OpenSslConnection>();

        session_resumption::<RustlsConnection, RustlsConnection>();
        session_resumption::<RustlsConnection, S2NConnection>();
        session_resumption::<RustlsConnection, OpenSslConnection>();

        session_resumption::<OpenSslConnection, OpenSslConnection>();
        session_resumption::<OpenSslConnection, S2NConnection>();
        session_resumption::<OpenSslConnection, RustlsConnection>();
    }
}
