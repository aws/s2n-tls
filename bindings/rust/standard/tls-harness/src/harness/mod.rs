// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
mod io;
pub use io::{LocalDataBuffer, TestPairIO, ViewIO};

use std::{error::Error, fmt::Debug, fs::read_to_string};
use strum::EnumIter;

#[derive(Clone, Copy, EnumIter)]
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
            PemType::ServerCertChain => "server-chain.pem",
            PemType::ClientKey => "client-key.pem",
            PemType::ClientCertChain => "client-cert.pem",
            PemType::CACert => "ca-cert.pem",
        }
    }
}

#[derive(Clone, Copy, Default, EnumIter)]
pub enum SigType {
    #[default]
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Ecdsa384,
    Ecdsa256,
}

impl SigType {
    pub fn get_dir_name(&self) -> &str {
        match self {
            SigType::Rsa2048 => "rsa2048",
            SigType::Rsa3072 => "rsa3072",
            SigType::Rsa4096 => "rsa4096",
            SigType::Ecdsa384 => "ecdsa384",
            SigType::Ecdsa256 => "ecdsa256",
        }
    }
}

impl Debug for SigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_dir_name())
    }
}

pub fn get_cert_path(pem_type: PemType, sig_type: SigType) -> String {
    const TEST_PEMS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/certs");

    format!(
        "{TEST_PEMS_PATH}/{}/{}",
        sig_type.get_dir_name(),
        pem_type.get_filename()
    )
}

pub fn read_to_bytes(pem_type: PemType, sig_type: SigType) -> Vec<u8> {
    read_to_string(get_cert_path(pem_type, sig_type))
        .unwrap()
        .into_bytes()
}

#[derive(Debug, Clone, Copy)]
pub enum Mode {
    Client,
    Server,
}

/// The TlsConnection object can be created from a corresponding config type.
pub trait TlsConnection: Sized {
    /// Library-specific config struct
    type Config;

    /// Make connection from existing config and buffer
    fn new_from_config(
        mode: Mode,
        config: &Self::Config,
        io: &TestPairIO,
    ) -> Result<Self, Box<dyn Error>>;

    /// Run one handshake step: receive msgs from other connection, process, and send new msgs
    fn handshake(&mut self) -> Result<(), Box<dyn Error>>;

    fn handshake_completed(&self) -> bool;

    /// Send `data` to the peer.
    ///
    /// Send is infailable because it communicates over local memory.
    fn send(&mut self, data: &[u8]);

    /// Read application data from the peer into `data`.
    fn recv(&mut self, data: &mut [u8]) -> std::io::Result<()>;

    /// Send a `CloseNotify` to the peer.
    ///
    /// This does not read the `CloseNotify` from the peer.
    ///
    /// Must be followed by a call to [`TlsConnection::shutdown_finish`] to ensure
    /// that any `CloseNotify` alerts from the peer are read.
    fn shutdown_send(&mut self);

    /// Attempt to read the `CloseNotify` from the peer.
    ///
    /// Returns `true` if the connection was successfully shutdown, `false` otherwise.
    ///
    /// The `CloseNotify` might already have been read by `shutdown_send`, depending
    /// on the order of client/server [`TlsConnection::shutdown_send`] calls.
    fn shutdown_finish(&mut self) -> bool;
}

pub trait TlsInfo: Sized {
    fn name() -> String;

    /// Return the IANA Description of the negotiated cipher suite.
    ///
    /// e.g. `TLS_AES_256_GCM_SHA384`
    fn get_negotiated_cipher_suite(&self) -> String;

    fn negotiated_tls13(&self) -> bool;

    /// Describes whether a connection was resumed.
    fn resumed_connection(&self) -> bool;

    /// For the rustls & openssl implementations, this only works for servers.
    fn mutual_auth(&self) -> bool;
}

pub trait TlsConfigBuilder {
    /// The config produced by the [`TlsConfigBuilder::build`] operation.
    type Config;

    fn new_test_config(mode: Mode) -> Self;

    /// Load a chain onto a config.
    ///
    /// This is most often used for servers.
    fn set_chain(&mut self, sig_type: SigType);

    /// Load a cert into a trust store.
    ///
    /// This is most often used for clients.
    fn set_trust(&mut self, sig_type: SigType);

    fn build(self) -> Self::Config;
}

/// A TlsConnPair owns the client and server tls connections along with the IO buffers.
pub struct TlsConnPair<C, S> {
    pub client: C,
    pub server: S,
    pub io: TestPairIO,
}

impl<C, S> TlsConnPair<C, S>
where
    C: TlsConnection,
    S: TlsConnection,
{
    pub fn from_configs(client_config: &C::Config, server_config: &S::Config) -> Self {
        let io = TestPairIO::default();
        let client = C::new_from_config(Mode::Client, client_config, &io).unwrap();
        let server = S::new_from_config(Mode::Server, server_config, &io).unwrap();
        Self { client, server, io }
    }

    pub fn client(&self) -> &C {
        &self.client
    }

    pub fn client_mut(&mut self) -> &mut C {
        &mut self.client
    }

    pub fn server(&self) -> &S {
        &self.server
    }

    pub fn server_mut(&mut self) -> &mut S {
        &mut self.server
    }

    /// Run handshake on connections
    /// Two round trips are needed for the server to receive the Finished message
    /// from the client and be ready to send data
    pub fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        for _ in 0..2 {
            self.client.handshake()?;
            self.server.handshake()?;
        }
        assert!(self.handshake_completed());
        Ok(())
    }

    /// Checks if handshake is finished for both client and server
    pub fn handshake_completed(&self) -> bool {
        self.client.handshake_completed() && self.server.handshake_completed()
    }

    /// Send data from client to server, and then from server to client
    pub fn round_trip_transfer(&mut self, data: &mut [u8]) -> std::io::Result<()> {
        // send data from client to server
        self.client.send(data);
        self.server.recv(data)?;

        // send data from server to client
        self.server.send(data);
        self.client.recv(data)?;

        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), Box<dyn Error>> {
        // These assertions do not _have_ to be true, but you are likely making
        // a mistake if you are hitting it. Generally all data should have been
        // read before attempting to shutdown
        assert_eq!(self.io.client_tx_stream.borrow().len(), 0);
        assert_eq!(self.io.server_tx_stream.borrow().len(), 0);

        self.client.shutdown_send();
        self.server.shutdown_send();

        let client_shutdown = self.client.shutdown_finish();
        let server_shutdown = self.server.shutdown_finish();
        if client_shutdown && server_shutdown {
            Ok(())
        } else {
            Err(
                format!("Shutdown Failed: client - {client_shutdown} server - {server_shutdown}")
                    .into(),
            )
        }
    }

    /// transfer `data_size` bytes between the client and the server.
    pub fn round_trip_assert(&mut self, data_size: usize) -> std::io::Result<()> {
        // we don't need "cryptographically random" data, just some non-zero data
        let mut random_data: Vec<u8> = (0..data_size).map(|i| (i * 101 % 256) as u8).collect();
        self.round_trip_transfer(&mut random_data)
    }
}

impl<C, S> TlsConnPair<C, S>
where
    C: TlsInfo,
    S: TlsInfo,
{
    pub fn get_negotiated_cipher_suite(&self) -> String {
        assert!(
            self.client.get_negotiated_cipher_suite() == self.server.get_negotiated_cipher_suite()
        );
        self.client.get_negotiated_cipher_suite()
    }

    pub fn negotiated_tls13(&self) -> bool {
        self.client.negotiated_tls13() && self.server.negotiated_tls13()
    }
}

pub struct TlsConfigBuilderPair<C, S> {
    pub client: C,
    pub server: S,
}

impl<C, S> Default for TlsConfigBuilderPair<C, S>
where
    C: TlsConfigBuilder,
    S: TlsConfigBuilder,
{
    fn default() -> Self {
        let mut pair = Self {
            client: C::new_test_config(Mode::Client),
            server: S::new_test_config(Mode::Server),
        };

        // set an RSA2048 cert as the default, because it is the most common
        // cert type.
        pair.client.set_trust(SigType::Rsa2048);
        pair.server.set_chain(SigType::Rsa2048);
        pair
    }
}

impl<C, S> TlsConfigBuilderPair<C, S>
where
    C: TlsConfigBuilder,
    S: TlsConfigBuilder,
{
    pub fn set_cert(&mut self, cert: SigType) {
        self.client.set_trust(cert);
        self.server.set_chain(cert);
    }

    pub fn build(self) -> (C::Config, S::Config) {
        (self.client.build(), self.server.build())
    }

    pub fn connection_pair<ClientConn, ServerConn>(self) -> TlsConnPair<ClientConn, ServerConn>
    where
        ClientConn: TlsConnection<Config = C::Config>,
        ServerConn: TlsConnection<Config = S::Config>,
    {
        let (client_config, server_config) = self.build();
        TlsConnPair::from_configs(&client_config, &server_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use strum::IntoEnumIterator;

    #[test]
    fn test_cert_paths_valid() {
        for pem_type in PemType::iter() {
            for sig_type in SigType::iter() {
                assert!(
                    Path::new(&get_cert_path(pem_type, sig_type)).exists(),
                    "cert not found"
                );
            }
        }
    }
}
