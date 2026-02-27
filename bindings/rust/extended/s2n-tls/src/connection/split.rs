// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The s2n-tls C library is designed to allow calling s2n_send and s2n_recv on separate threads
//! safely. This module extends that behavior into our Rust bindings by splitting apart the
//! Connection into a read half and a write half. This enables users to send and recv on
//! separate tasks without having to wrap the Connection in a mutex.

use crate::{connection::Connection, error::Error};
use std::task::Poll;

impl Connection {
    pub fn split(self) -> (ReadHalf, WriteHalf) {
        (
            ReadHalf { conn: self.clone() },
            WriteHalf { conn: self.clone() },
        )
    }
}

pub struct ReadHalf {
    conn: Connection,
}

impl ReadHalf {
    pub fn poll_recv(&mut self, buf: &mut [u8]) -> Poll<Result<usize, Error>> {
        self.conn.poll_recv(buf)
    }
}
pub struct WriteHalf {
    conn: Connection,
}

impl WriteHalf {
    pub fn poll_send(&mut self, buf: &mut [u8]) -> Poll<Result<usize, Error>> {
        self.conn.poll_send(buf)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::Error,
        security,
        testing::{build_config, TestPair},
    };
    use openssl::rand::rand_bytes;
    use std::{
        task::Poll,
        thread::{self},
    };

    /* This is in a separate function since receive logic is kind of tedious in s2n-tls as
     * you are only able to receive one record at a time. */
    fn receive<F>(mut poll_recv: F, mut recv_buffer: Vec<u8>, expected_output: Vec<u8>)
    where
        F: FnMut(&mut [u8]) -> Poll<Result<usize, Error>>,
    {
        let mut total_data_recv = 0;
        while total_data_recv != expected_output.len() {
            let recv_len = match poll_recv(&mut recv_buffer[total_data_recv..]) {
                Poll::Ready(res) => match res {
                    Ok(len) => len,
                    Err(_) => 0,
                },
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
        let mut client_data = test_data.to_vec();
        let mut server_data = test_data.to_vec();

        /* Split the client */
        let (mut read, mut write) = test_pair.client.split();

        assert!(test_pair.server.poll_send(&mut server_data).is_ready());

        // Test parallel reads/writes by sending the client halves to separate threads
        let recv = thread::spawn(move || {
            receive(|buf| read.poll_recv(buf), client_recv_buffer, server_data);
        });
        let send = thread::spawn(move || {
            assert!(write.poll_send(&mut client_data).is_ready());
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
}
