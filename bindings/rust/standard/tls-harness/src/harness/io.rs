// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    cell::RefCell, collections::VecDeque, io::{BufRead, ErrorKind}, rc::Rc, sync::atomic::{AtomicBool, Ordering}
};

use brass_aphid_wire_decryption::decryption::stream_decrypter::StreamDecrypter;
use byteorder::{BigEndian, ReadBytesExt};

use crate::Mode;

pub type LocalDataBuffer = RefCell<VecDeque<u8>>;

#[derive(Debug, Default)]
pub struct TestPairIO {
    /// a data buffer that the server writes to and the client reads from
    pub server_tx_stream: LocalDataBuffer,
    /// a data buffer that the client writes to and the server reads from
    pub client_tx_stream: LocalDataBuffer,

    /// indicates whether all client/server writes should be stored to the
    /// transcript fields
    pub recording: AtomicBool,
    pub client_tx_transcript: RefCell<Vec<u8>>,
    pub server_tx_transcript: RefCell<Vec<u8>>,
    /// [`Self::enable_decryption`] will initialize the stream decrypter, which
    /// allows tests to make assertions on the decrypted TLS transcript.
    ///
    /// This is especially useful for TLS 1.3 where much of the handshake is encrypted.
    pub decrypter: RefCell<Option<StreamDecrypter>>,
}

impl TestPairIO {
    pub fn client_view(self: &Rc<Self>) -> ViewIO {
        ViewIO {
            identity: Mode::Client,
            io: Rc::clone(self),
        }
    }

    pub fn server_view(self: &Rc<Self>) -> ViewIO {
        ViewIO {
            identity: Mode::Server,
            io: Rc::clone(self),
        }
    }

    pub fn enable_recording(&self) {
        self.recording.store(true, Ordering::Relaxed);
    }

    /// Note: this is only available for TLS 1.3
    pub fn enable_decryption(
        &self,
        keys: brass_aphid_wire_decryption::decryption::key_manager::KeyManager,
    ) {
        let stream_decrypter = StreamDecrypter::new(keys);
        *self.decrypter.borrow_mut() = Some(stream_decrypter);
    }

    pub fn client_record_sizes(&self) -> Vec<u16> {
        Self::record_sizes(self.client_tx_transcript.borrow().as_slice()).unwrap()
    }

    pub fn server_record_sizes(&self) -> Vec<u16> {
        Self::record_sizes(self.server_tx_transcript.borrow().as_slice()).unwrap()
    }

    /// Return a list of the record sizes contained in `buffer`.
    ///
    /// Note that this is always the length of the outer, obfuscated record, and
    /// therefore includes padding.
    ///
    /// Data is expected to be well formed. If `buffer` contains partial records
    /// this method will return an error.
    fn record_sizes(mut buffer: &[u8]) -> std::io::Result<Vec<u16>> {
        let mut record_lengths = Vec::new();
        while !buffer.is_empty() {
            let _content_type = buffer.read_u8()?;
            let _protocol = buffer.read_u16::<BigEndian>()?;
            let length = buffer.read_u16::<BigEndian>()?;
            record_lengths.push(length);
            buffer.consume(length as usize);
        }
        Ok(record_lengths)
    }
}

/// A "view" of the IO.
///
/// This view is client/server specific, and notably implements the read and write
/// traits.
pub struct ViewIO {
    pub identity: Mode,
    pub io: Rc<TestPairIO>,
}

impl ViewIO {
    fn recv_ctx(&self) -> &LocalDataBuffer {
        match self.identity {
            Mode::Client => &self.io.server_tx_stream,
            Mode::Server => &self.io.client_tx_stream,
        }
    }

    fn send_ctx(&self) -> &LocalDataBuffer {
        match self.identity {
            Mode::Client => &self.io.client_tx_stream,
            Mode::Server => &self.io.server_tx_stream,
        }
    }

    fn send_transcript(&self) -> &RefCell<Vec<u8>> {
        match self.identity {
            Mode::Client => &self.io.client_tx_transcript,
            Mode::Server => &self.io.server_tx_transcript,
        }
    }
}

impl std::io::Read for ViewIO {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let res = self.recv_ctx().borrow_mut().read(buf);
        if let Ok(0) = res {
            // We are "faking" a TcpStream, where a read of length 0 indicates
            // EoF. That is incorrect for this scenario. Instead we return WouldBlock
            // to indicate that there is simply no more data to be read.
            Err(std::io::Error::new(ErrorKind::WouldBlock, "blocking"))
        } else {
            res
        }
    }
}

impl std::io::Write for ViewIO {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let write_result = self.send_ctx().borrow_mut().write(buf);

        // if we successfully wrote data, we need to record it in the various test
        // utilities.
        if let Ok(written) = write_result {
            // recorder
            if self.io.recording.load(Ordering::Relaxed) {
                self.send_transcript()
                    .borrow_mut()
                    .write_all(&buf[0..written])
                    .unwrap();
            }

            // decrypter
            let mut decrypter = self.io.decrypter.borrow_mut();
            if let Some(decrypter) = decrypter.as_mut() {
                let wire_mode = match self.identity {
                    Mode::Client => brass_aphid_wire_decryption::decryption::Mode::Client,
                    Mode::Server => brass_aphid_wire_decryption::decryption::Mode::Server,
                };
                decrypter.record_tx(&buf[0..written], wire_mode);
                decrypter.decrypt_records(wire_mode).unwrap();
            }
        }

        write_result
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use openssl::ssl::SslContextBuilder;

    use crate::{
        cohort::{rustls::RustlsConfigBuilder, OpenSslConnection, RustlsConnection, S2NConnection},
        harness::TlsConfigBuilderPair,
        TlsConnPair,
    };

    use super::*;

    #[test]
    fn recording_off_by_default() {
        let io = TestPairIO::default();
        assert!(!io.recording.load(Ordering::Relaxed));
    }

    /// return the most frequently occurring number in `data`
    fn mode(data: &Vec<u16>) -> u16 {
        let mut count: HashMap<u16, usize> = HashMap::new();
        for d in data {
            let count = count.entry(*d).or_default();
            *count += 1;
        }

        let mut counts: Vec<(u16, usize)> = count.into_iter().collect();
        counts.sort_by_key(|(_element, count)| *count);
        counts.last().unwrap().0
    }

    /// our "record size" methods should correctly report the defaults for various
    /// implementations
    #[test]
    fn implementation_record_size() {
        const S2N_RECORD_DEFAULT: u16 = 8104;
        const OPENSSL_RECORD_DEFAULT: u16 = 16401;
        const RUSTLS_RECORD_DEFAULT: u16 = 16401;

        // openssl & s2n
        {
            let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
                let configs =
                    TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
                configs.connection_pair()
            };
            pair.io.enable_recording();

            pair.handshake().unwrap();
            assert!(pair.round_trip_assert(100_000).is_ok());
            pair.shutdown().unwrap();

            let openssl_record = mode(&pair.io.client_record_sizes());
            let s2n_record = mode(&pair.io.server_record_sizes());

            assert_eq!(openssl_record, OPENSSL_RECORD_DEFAULT);
            assert_eq!(s2n_record, S2N_RECORD_DEFAULT);
        }

        // s2n & rustls
        {
            let mut pair: TlsConnPair<S2NConnection, RustlsConnection> = {
                let configs =
                    TlsConfigBuilderPair::<s2n_tls::config::Builder, RustlsConfigBuilder>::default(
                    );
                configs.connection_pair()
            };
            pair.io.enable_recording();

            pair.handshake().unwrap();
            assert!(pair.round_trip_assert(100_000).is_ok());
            pair.shutdown().unwrap();

            let s2n_record = mode(&pair.io.client_record_sizes());
            let rustls_record = mode(&pair.io.server_record_sizes());

            assert_eq!(s2n_record, S2N_RECORD_DEFAULT);
            assert_eq!(rustls_record, RUSTLS_RECORD_DEFAULT);
        }
    }
}
