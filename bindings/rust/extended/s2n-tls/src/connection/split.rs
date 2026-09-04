// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The s2n-tls C library is designed to allow calling s2n_send and s2n_recv on separate threads
//! safely. This module extends that behavior into our Rust bindings by splitting apart the
//! Connection into a read half and a write half. This enables users to send and recv on
//! separate tasks without having to wrap the Connection in a mutex.

use crate::{connection::Connection, error::Error};
use std::{mem::MaybeUninit, ops::Deref, sync::Arc, task::Poll};

impl Connection {
    pub fn split(self) -> (ReadHalf, WriteHalf) {
        let conn = Arc::new(self);
        (
            ReadHalf { conn: conn.clone() },
            WriteHalf { conn: conn.clone() },
        )
    }
}

pub fn reunite(read_half: ReadHalf, write_half: WriteHalf) -> Option<Connection> {
    // First we drop one of the halves. Then we can use the into_inner function
    // to return the inner Connection since there is only one reference left.
    drop(read_half);
    Arc::into_inner(write_half.conn)
}

// Be very careful about expanding functionality for the Read/Write halves. Note that the only
// thread-safety guarantee that the s2n-tls C library advertises is the ability to send and recv
// on separate threads. Adding extra Connection functions that mutate the connection needs to be
// carefully thought through. For example, it would not be safe to negotiate a TLS connection
// through the halves due to the way that handshake buffer is shared between reader and writer.
pub struct ReadHalf {
    conn: Arc<Connection>,
}

impl ReadHalf {
    pub fn poll_recv(&mut self, buf: &mut [u8]) -> Poll<Result<usize, Error>> {
        unsafe { self.conn.immutable_poll_recv(buf) }
    }
    pub fn poll_recv_uninitialized(
        &mut self,
        buf: &mut [MaybeUninit<u8>],
    ) -> Poll<Result<usize, Error>> {
        unsafe { self.conn.immutable_poll_recv_uninitialized(buf) }
    }
}

impl Deref for ReadHalf {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}
pub struct WriteHalf {
    conn: Arc<Connection>,
}

impl WriteHalf {
    pub fn poll_send(&mut self, buf: &[u8]) -> Poll<Result<usize, Error>> {
        unsafe { self.conn.immutable_poll_send(buf) }
    }

    pub fn poll_shutdown_send(&mut self) -> Poll<Result<(), Error>> {
        unsafe { self.conn.immutable_poll_shutdown_send() }
    }
}

impl Deref for WriteHalf {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        config,
        connection::{split::reunite, Connection},
        error::Error,
        security,
        testing::{
            build_config,
            test::{openssl_handshake, ServerTestStream},
            CertKeyPair, InsecureAcceptAllCertificatesHandler, TestPair,
        },
    };
    use bytes::BytesMut;
    use foreign_types::ForeignTypeRef;
    use openssl::{
        rand::rand_bytes,
        ssl::{Ssl, SslContext, SslFiletype, SslMethod, SslStream, SslVerifyMode, SslVersion},
    };
    use std::{
        io::{Read, Write},
        task::Poll,
        thread::{self},
    };

    /* Contains tedious recv logic to receive multiple records; in s2n-tls poll_recv only returns
     * one record at a time. */
    #[track_caller]
    fn receive<F>(mut poll_recv: F, mut recv_buffer: Vec<u8>, expected_output: Vec<u8>)
    where
        F: FnMut(&mut [u8]) -> Poll<Result<usize, Error>>,
    {
        let mut total_data_recv = 0;
        while total_data_recv != expected_output.len() {
            let recv_len = match poll_recv(&mut recv_buffer[total_data_recv..]) {
                Poll::Ready(res) => res.unwrap_or_default(),
                Poll::Pending => 0,
            };
            assert_ne!(recv_len, 0);
            total_data_recv += recv_len;
        }
        assert_eq!(recv_buffer, expected_output);
    }

    pub fn send_and_recv(test_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        /* Initial handshake */
        let config = build_config(&security::DEFAULT).unwrap();
        let mut test_pair = TestPair::from_config(&config);
        assert!(test_pair.handshake().is_ok());

        /* Instantiate buffers */
        let client_recv_buffer = vec![0; test_data.len()];
        let server_recv_buffer = vec![0; test_data.len()];
        let client_data = test_data.to_vec();
        let server_data = test_data.to_vec();

        /* Split the client */
        let (mut read, mut write) = test_pair.client.split();

        assert!(test_pair.server.poll_send(&server_data).is_ready());

        // Test parallel reads/writes by sending the client halves to separate threads
        let recv = thread::spawn(move || {
            receive(|buf| read.poll_recv(buf), client_recv_buffer, server_data);
            read
        });
        let send = thread::spawn(move || {
            assert!(write.poll_send(&client_data).is_ready());
            write
        });
        let mut write = send.join().unwrap();
        let mut read = recv.join().unwrap();

        receive(
            |buf| test_pair.server.poll_recv(buf),
            server_recv_buffer,
            test_data.to_vec(),
        );

        // Check that all sides of the connection can send and recv shutdown gracefully
        assert!(write.poll_shutdown_send().is_ready());
        assert!(matches!(
            test_pair.server.poll_shutdown_send(),
            Poll::Ready(Result::Ok { .. })
        ));
        let mut buf = vec![0; test_data.len()];
        assert!(matches!(
            test_pair.server.poll_recv(&mut buf),
            Poll::Ready(Result::Ok(0))
        ));
        assert!(matches!(
            read.poll_recv(&mut buf),
            Poll::Ready(Result::Ok(0))
        ));

        Ok(())
    }

    pub fn send_and_recv_uninitialized(test_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        /* Initial handshake */
        let config = build_config(&security::DEFAULT).unwrap();
        let mut test_pair = TestPair::from_config(&config);
        assert!(test_pair.handshake().is_ok());

        /* Instantiate buffers */
        let test_data_len = test_data.len();
        let mut client_recv_buffer = BytesMut::new();
        client_recv_buffer.reserve(test_data_len);
        let server_recv_buffer = vec![0; test_data_len];
        let client_data = test_data.to_vec();
        let server_data = test_data.to_vec();

        /* Split the client */
        let (mut read, mut write) = test_pair.client.split();

        assert!(test_pair.server.poll_send(&server_data).is_ready());

        // Test parallel reads/writes by sending the client halves to separate threads
        let recv = thread::spawn(move || {
            while client_recv_buffer.len() != server_data.len() {
                let uninit = client_recv_buffer.spare_capacity_mut();
                let size = match read.poll_recv_uninitialized(uninit) {
                    Poll::Ready(res) => res.unwrap_or_default(),
                    Poll::Pending => 0,
                };
                assert_ne!(size, 0);
                let old_len = client_recv_buffer.len();
                unsafe {
                    client_recv_buffer.set_len(
                        old_len
                            .checked_add(size)
                            .expect("Overflow should not occur"),
                    );
                }
            }
            assert_eq!(client_recv_buffer, server_data);
        });
        let send = thread::spawn(move || {
            assert!(write.poll_send(&client_data).is_ready());
        });
        assert!(send.join().is_ok());
        assert!(recv.join().is_ok());

        receive(
            |buf| test_pair.server.poll_recv(buf),
            server_recv_buffer,
            test_data.to_vec(),
        );
        Ok(())
    }

    #[test]
    pub fn send_and_recv_small() -> Result<(), Box<dyn std::error::Error>> {
        send_and_recv(b"hello")
    }

    #[test]
    pub fn send_and_recv_large_random() -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = [0; 1024 * 1024];
        rand_bytes(&mut buf).unwrap();
        send_and_recv(&buf)
    }

    #[test]
    pub fn send_and_recv_uninitialized_small() -> Result<(), Box<dyn std::error::Error>> {
        send_and_recv_uninitialized(b"hello")
    }

    #[test]
    pub fn send_and_recv_uninitialized_large_random() -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = [0; 1024 * 1024];
        rand_bytes(&mut buf).unwrap();
        send_and_recv_uninitialized(&buf)
    }

    /// Verify that a client connection can be split into halves, used, then
    /// reunited back into a single Connection that remains usable for IO.
    #[test]
    pub fn split_reunite_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let pre_reunite_msg = b"hello from split halves";
        let post_reunite_msg = b"hello from reunited connection";

        /* Initial handshake */
        let config = build_config(&security::DEFAULT).unwrap();
        let mut test_pair = TestPair::from_config(&config);
        assert!(test_pair.handshake().is_ok());

        /* Split the client, exchange data via the halves, then reunite */
        let (mut read, mut write) = test_pair.client.split();

        // client -> server via the write half
        assert!(write.poll_send(pre_reunite_msg).is_ready());
        let mut server_recv_buffer = vec![0; pre_reunite_msg.len()];
        receive(
            |buf| test_pair.server.poll_recv(buf),
            server_recv_buffer.clone(),
            pre_reunite_msg.to_vec(),
        );

        // server -> client via the read half
        assert!(test_pair.server.poll_send(pre_reunite_msg).is_ready());
        let client_recv_buffer = vec![0; pre_reunite_msg.len()];
        receive(
            |buf| read.poll_recv(buf),
            client_recv_buffer,
            pre_reunite_msg.to_vec(),
        );

        // Reunite the two halves back into a single Connection.
        let mut client = reunite(read, write).expect("Only two references exist to the Connection");

        /* The reunited connection should still be usable for both send and recv,
         * proving that the underlying s2n-tls connection state was preserved. */
        assert!(client.poll_send(post_reunite_msg).is_ready());
        server_recv_buffer.resize(post_reunite_msg.len(), 0);
        receive(
            |buf| test_pair.server.poll_recv(buf),
            server_recv_buffer,
            post_reunite_msg.to_vec(),
        );

        assert!(test_pair.server.poll_send(post_reunite_msg).is_ready());
        let client_recv_buffer = vec![0; post_reunite_msg.len()];
        receive(
            |buf| client.poll_recv(buf),
            client_recv_buffer,
            post_reunite_msg.to_vec(),
        );

        Ok(())
    }

    // Check that an s2n-tls split connection can continue to read and write data after
    // reading a key update requested message. s2n-tls itself never sends key update requested
    // messages, so we use Openssl as a peer to generate the key update request.
    #[test]
    fn peer_requested_key_update_after_split() -> Result<(), Box<dyn std::error::Error>> {
        const SERVER_DATA: &[u8] = b"beep boop";
        const CLIENT_DATA: &[u8] = b"boop beep";

        let (mut client, mut server) = key_update_test_pair()?;
        openssl_handshake(&mut client, &mut server)?;

        // Split the client into independent read and write halves.
        let (mut read, mut write) = client.split();

        let ssl_ptr = server.ssl().as_ptr();
        let rc = unsafe { SSL_key_update(ssl_ptr, SSL_KEY_UPDATE_REQUESTED) };
        assert_eq!(rc, 1, "SSL_key_update should succeed");

        // This write will flush the key update message before sending SERVER_DATA.
        server.write_all(SERVER_DATA)?;

        // Decrypting SERVER_DATA correctly proves the read half handled the peer's key update.
        let recv_buffer = vec![0; SERVER_DATA.len()];
        receive(|buf| read.poll_recv(buf), recv_buffer, SERVER_DATA.to_vec());

        // The write half sends data. Because openssl requested a key update,
        // s2n-tls sends its own KeyUpdate record (updating its sending key) ahead
        // of the application data.
        assert!(write.poll_send(CLIENT_DATA).is_ready());

        // openssl reads the data, processing the s2n-tls KeyUpdate record and
        // updating its receiving key. Decrypting CLIENT_DATA correctly proves the
        // write half's key update was accepted by the peer.
        let mut server_recv = vec![0; CLIENT_DATA.len()];
        server.read_exact(&mut server_recv)?;
        assert_eq!(server_recv, CLIENT_DATA);

        #[cfg(all(feature = "unstable-ktls", not(windows)))]
        {
            let counts = read.key_update_counts()?;
            assert_eq!(counts.recv_key_updates, 1, "read half updated the recv key");
            assert_eq!(
                counts.send_key_updates, 1,
                "write half updated the send key"
            );
        }

        Ok(())
    }

    // openssl-sys does not expose the key update API, so we declare it manually.
    // See https://docs.openssl.org/master/man3/SSL_key_update/
    extern "C" {
        fn SSL_key_update(s: *mut openssl_sys::SSL, update_type: libc::c_int) -> libc::c_int;
    }

    // Update our own sending key AND request that the peer update its sending key.
    const SSL_KEY_UPDATE_REQUESTED: libc::c_int = 1;

    fn key_update_test_pair(
    ) -> Result<(Connection, SslStream<ServerTestStream>), Box<dyn std::error::Error>> {
        let certs = CertKeyPair::from_path(
            "permutations/rsae_pkcs_4096_sha384/",
            "server-chain",
            "server-key",
            "ca-cert",
        );

        // Build the s2n-tls client. Key updates require TLS1.3.
        let mut builder = config::Builder::new();
        builder.set_security_policy(&security::DEFAULT_TLS13)?;
        builder.trust_pem(certs.ca_cert())?;
        builder.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
        builder.with_system_certs(false)?;
        let config = builder.build()?;
        let s2n_pair = TestPair::from_config(&config);
        let client = s2n_pair.client;

        // Build the openssl server, restricted to TLS1.3.
        let mut ctx_builder = SslContext::builder(SslMethod::tls_server())?;
        ctx_builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        ctx_builder.set_certificate_chain_file(certs.cert_path())?;
        ctx_builder.set_private_key_file(certs.key_path(), SslFiletype::PEM)?;
        ctx_builder.set_verify(SslVerifyMode::NONE);
        let openssl_ctx = ctx_builder.build();
        let openssl_ssl = Ssl::new(&openssl_ctx)?;

        // Connect the openssl server to the same IO that the s2n-tls client uses.
        let server = SslStream::new(openssl_ssl, ServerTestStream(s2n_pair.io))?;

        Ok((client, server))
    }
}
