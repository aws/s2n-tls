// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    cell::RefCell,
    collections::VecDeque,
    io::{BufRead, ErrorKind},
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};

use byteorder::{BigEndian, ReadBytesExt};

pub type LocalDataBuffer = RefCell<VecDeque<u8>>;

#[derive(Debug, Default)]
pub struct TestPairIO {
    /// a data buffer that the server writes to and the client reads from
    pub server_tx_stream: Rc<LocalDataBuffer>,
    /// a data buffer that the client writes to and the server reads from
    pub client_tx_stream: Rc<LocalDataBuffer>,

    pub recording: Rc<AtomicBool>,
    pub client_tx_transcript: Rc<RefCell<Vec<u8>>>,
    pub server_tx_transcript: Rc<RefCell<Vec<u8>>>,
}

impl TestPairIO {
    pub fn client_view(&self) -> ViewIO {
        ViewIO {
            send_ctx: self.client_tx_stream.clone(),
            recv_ctx: self.server_tx_stream.clone(),
            recording: self.recording.clone(),
            send_transcript: self.client_tx_transcript.clone(),
        }
    }

    pub fn server_view(&self) -> ViewIO {
        ViewIO {
            send_ctx: self.server_tx_stream.clone(),
            recv_ctx: self.client_tx_stream.clone(),
            recording: self.recording.clone(),
            send_transcript: self.server_tx_transcript.clone(),
        }
    }

    pub fn enable_recording(&mut self) {
        self.recording.store(true, Ordering::Relaxed);
    }

    pub fn client_record_sizes(&self) -> Vec<u16> {
        Self::record_sizes(self.client_tx_transcript.as_ref().borrow().as_slice()).unwrap()
    }

    pub fn server_record_sizes(&self) -> Vec<u16> {
        Self::record_sizes(self.server_tx_transcript.as_ref().borrow().as_slice()).unwrap()
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
///
// This struct is used by Openssl and Rustls which both rely on a "stream" abstraction
// which implements read and write. This is not used by s2n-tls, which relies on
// lower level callbacks.
pub struct ViewIO {
    pub send_ctx: Rc<LocalDataBuffer>,
    pub recv_ctx: Rc<LocalDataBuffer>,
    pub recording: Rc<AtomicBool>,
    pub send_transcript: Rc<RefCell<Vec<u8>>>,
}

impl std::io::Read for ViewIO {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let res = self.recv_ctx.borrow_mut().read(buf);
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
        let write_result = self.send_ctx.borrow_mut().write(buf);

        if self.recording.load(Ordering::Relaxed) {
            if let Ok(written) = write_result {
                self.send_transcript
                    .borrow_mut()
                    .write_all(&buf[0..written])
                    .unwrap();
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
