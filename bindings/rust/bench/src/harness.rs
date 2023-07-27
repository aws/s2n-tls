// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{get_cert_path, PemType};
use std::{
    cell::RefCell,
    collections::VecDeque,
    error::Error,
    fs::read_to_string,
    io::{ErrorKind, Read, Write},
    rc::Rc,
};

pub fn read_to_bytes(pem_type: PemType, sig_type: SigType) -> Vec<u8> {
    read_to_string(get_cert_path(pem_type, sig_type))
        .unwrap()
        .into_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HandshakeType {
    #[default]
    ServerAuth,
    MutualAuth,
}

// these parameters were the only ones readily usable for all three libaries:
// s2n-tls, rustls, and openssl
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CipherSuite {
    #[default]
    AES_128_GCM_SHA256,
    AES_256_GCM_SHA384,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ECGroup {
    SECP256R1,
    #[default]
    X25519,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SigType {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    #[default]
    Ec384,
}

impl SigType {
    pub fn get_dir_name(&self) -> &str {
        match self {
            SigType::Rsa2048 => "rsa2048",
            SigType::Rsa3072 => "rsa3072",
            SigType::Rsa4096 => "rsa4096",
            SigType::Ec384 => "ec384",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CryptoConfig {
    pub cipher_suite: CipherSuite,
    pub ec_group: ECGroup,
    pub sig_type: SigType,
}

impl CryptoConfig {
    pub fn new(cipher_suite: CipherSuite, ec_group: ECGroup, sig_type: SigType) -> Self {
        Self {
            cipher_suite,
            ec_group,
            sig_type,
        }
    }
}

pub trait TlsBenchHarness: Sized {
    /// Default harness
    fn default() -> Result<Self, Box<dyn Error>> {
        Self::new(
            CryptoConfig::default(),
            HandshakeType::default(),
            ConnectedBuffer::default(),
        )
    }

    /// Initialize buffers, configs, and connections (pre-handshake)
    fn new(
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
        buffer: ConnectedBuffer,
    ) -> Result<Self, Box<dyn Error>>;

    /// Run handshake on initialized connections
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
        let recv = Rc::new(RefCell::new(VecDeque::new()));
        let send = Rc::new(RefCell::new(VecDeque::new()));

        // prevent resizing of buffers, useful for memory bench
        recv.borrow_mut().reserve(10000);
        send.borrow_mut().reserve(10000);

        Self { recv, send }
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
        let res = self.recv.borrow_mut().read(dest);
        match res {
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

impl Default for ConnectedBuffer {
    fn default() -> Self {
        Self::new()
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
            use SigType::*;

            #[test]
            fn test_handshake_config() {
                for handshake_type in [ServerAuth, MutualAuth] {
                    for cipher_suite in [AES_128_GCM_SHA256, AES_256_GCM_SHA384] {
                        for ec_group in [SECP256R1, X25519] {
                            for sig_type in [Ec384, Rsa2048, Rsa3072, Rsa4096] {
                                let crypto_config = CryptoConfig::new(cipher_suite, ec_group, sig_type);
                                let mut harness = <$harness_type>::new(crypto_config, handshake_type, ConnectedBuffer::default()).unwrap();

                                assert!(!harness.handshake_completed());
                                harness.handshake().unwrap();
                                assert!(harness.handshake_completed());

                                assert!(harness.negotiated_tls13());
                                assert_eq!(cipher_suite, harness.get_negotiated_cipher_suite());
                            }
                        }
                    }
                }
            }

            #[test]
            fn test_transfer() {
                // use a large buffer to test across TLS record boundaries
                let mut buf = [0x56u8; 1000000];
                for cipher_suite in [AES_128_GCM_SHA256, AES_256_GCM_SHA384] {
                    let crypto_config = CryptoConfig::new(cipher_suite, ECGroup::default(), SigType::default());
                    let mut harness = <$harness_type>::new(crypto_config, HandshakeType::default(), ConnectedBuffer::default()).unwrap();
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
    #[cfg(feature = "openssl")]
    use crate::OpenSslHarness;
    #[cfg(feature = "rustls")]
    use crate::RustlsHarness;
    use crate::{S2NHarness, TlsBenchHarness};

    test_tls_bench_harnesses! {
        s2n_tls: S2NHarness,
    }
    #[cfg(feature = "rustls")]
    test_tls_bench_harnesses! {
        rustls: RustlsHarness,
    }
    #[cfg(feature = "openssl")]
    test_tls_bench_harnesses! {
        openssl: OpenSslHarness,
    }
}
