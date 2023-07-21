// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    cell::RefCell,
    collections::VecDeque,
    error::Error,
    fs::read_to_string,
    io::{ErrorKind, Read, Write},
    rc::Rc,
};

pub fn read_to_bytes(path: &str) -> Vec<u8> {
    read_to_string(path).unwrap().into_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Client,
    Server,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    #[default]
    ServerAuth,
    MutualAuth,
}

// these parameters were the only ones readily usable for all three libaries:
// s2n-tls, rustls, and openssl
#[allow(non_camel_case_types)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    #[default]
    AES_128_GCM_SHA256,
    AES_256_GCM_SHA384,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ECGroup {
    SECP256R1,
    #[default]
    X25519,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CryptoConfig {
    pub cipher_suite: CipherSuite,
    pub ec_group: ECGroup,
}

pub trait TlsBenchHarness: Sized {
    /// Default harness
    fn default() -> Result<Self, Box<dyn Error>> {
        Self::new(Default::default(), Default::default())
    }

    /// Initialize buffers, configs, and connections (pre-handshake)
    fn new(
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>>;

    /// Run handshake on initialized connection
    /// Returns error if handshake has already completed
    fn handshake(&mut self) -> Result<(), Box<dyn Error>>;

    /// Checks if handshake is finished for both client and server
    fn handshake_completed(&self) -> bool;

    /// Get negotiated cipher suite
    fn get_negotiated_cipher_suite(&self) -> CipherSuite;

    /// Get whether or negotiated version is TLS1.3
    fn negotiated_tls13(&self) -> bool;

    /// Send application data from connection in harness pair
    fn send(&mut self, sender: Mode, data: &[u8]) -> Result<(), Box<dyn Error>>;

    /// Receive application data sent to connection in harness pair
    fn recv(&mut self, receiver: Mode, data: &mut [u8]) -> Result<(), Box<dyn Error>>;

    /// Send data from client to server and then from server to client
    fn round_trip_transfer(&mut self, data: &mut [u8]) -> Result<(), Box<dyn Error>> {
        // send data from client to server
        self.send(Mode::Client, data)?;
        self.recv(Mode::Server, data)?;

        // send data from server to client
        self.send(Mode::Server, data)?;
        self.recv(Mode::Client, data)?;

        Ok(())
    }
}

/// Wrapper of two shared buffers to pass as stream
/// This wrapper `read()`s into one buffer and `write()`s to another
#[derive(Clone)]
pub struct ConnectedBuffer {
    recv: Rc<RefCell<VecDeque<u8>>>,
    send: Rc<RefCell<VecDeque<u8>>>,
}

impl ConnectedBuffer {
    /// Make a new struct with new internal buffers
    pub fn new() -> Self {
        Self {
            recv: Rc::new(RefCell::new(VecDeque::new())),
            send: Rc::new(RefCell::new(VecDeque::new())),
        }
    }
    /// Make a new struct that shares internal buffers but swapped, ex.
    /// `write()` writes to the buffer that the inverse `read()`s from
    pub fn clone_inverse(&self) -> Self {
        Self {
            recv: Rc::clone(&self.send),
            send: Rc::clone(&self.recv),
        }
    }
}

impl Read for ConnectedBuffer {
    fn read(&mut self, dest: &mut [u8]) -> Result<usize, std::io::Error> {
        match self.recv.borrow_mut().read(dest) {
            // rustls expects WouldBlock on read of length 0
            Ok(0) => Err(std::io::Error::new(ErrorKind::WouldBlock, "blocking")),
            Ok(len) => Ok(len),
            Err(err) => Err(err),
        }
    }
}

impl Write for ConnectedBuffer {
    fn write(&mut self, src: &[u8]) -> Result<usize, std::io::Error> {
        self.send.borrow_mut().write(src)
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(()) // data already available to destination
    }
}

#[cfg(test)]
macro_rules! test_tls_bench_harnesses {
    ($($lib_name:ident: $harness_type:ty,)*) => {
    $(
        mod $lib_name {
            use super::*;
            use CipherSuite::*;
            use ECGroup::*;
            use HandshakeType::*;

            #[test]
            fn test_handshake_config() {
                for handshake_type in [ServerAuth, MutualAuth] {
                    for cipher_suite in [AES_128_GCM_SHA256, AES_256_GCM_SHA384] {
                        for ec_group in [SECP256R1, X25519] {
                            let crypto_config = CryptoConfig { cipher_suite: cipher_suite.clone(), ec_group: ec_group.clone() };
                            let mut harness = <$harness_type>::new(crypto_config, handshake_type).unwrap();

                            assert!(!harness.handshake_completed());
                            harness.handshake().unwrap();
                            assert!(harness.handshake_completed());

                            assert!(harness.negotiated_tls13());
                            assert_eq!(cipher_suite, harness.get_negotiated_cipher_suite());
                        }
                    }
                }
            }

            #[test]
            fn test_transfer() {
                // use a large buffer to test across TLS record boundaries
                let mut buf = [0x56u8; 1000000];
                let (mut harness, mut crypto_config);
                for cipher_suite in [AES_128_GCM_SHA256, AES_256_GCM_SHA384] {
                    crypto_config = CryptoConfig { cipher_suite: cipher_suite, ec_group: Default::default() };
                    harness = <$harness_type>::new(crypto_config, Default::default()).unwrap();
                    harness.handshake().unwrap();
                    harness.round_trip_transfer(&mut buf).unwrap();
                }
            }
        }
    )*
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OpenSslHarness, RustlsHarness, S2NHarness, TlsBenchHarness};

    test_tls_bench_harnesses! {
        s2n_tls: S2NHarness,
        rustls: RustlsHarness,
        openssl: OpenSslHarness,
    }
}
