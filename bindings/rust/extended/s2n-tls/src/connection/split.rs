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
        connection::split::reunite,
        error::Error,
        security,
        testing::{build_config, TestPair},
    };
    use bytes::BytesMut;
    use openssl::rand::rand_bytes;
    use std::{
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
        });
        let send = thread::spawn(move || {
            assert!(write.poll_send(&client_data).is_ready());
            assert!(write.poll_shutdown_send().is_ready());
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
}
