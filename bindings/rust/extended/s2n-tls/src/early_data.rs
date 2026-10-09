// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Methods to send and receive TLS 1.3 early data (0-RTT).
//!
//! Early data requires session resumption or an external pre-shared key configured for
//! early data (see [`crate::psk::Builder::configure_early_data`] and
//! [`crate::config::Builder::set_server_max_early_data_size`]).
//!
//! # Warning
//!
//! Early data is transferred before the handshake completes, so it is not forward secret
//! and is vulnerable to replay attacks. See the
//! [early data usage guide](https://aws.github.io/s2n-tls/usage-guide/ch15-early-data.html)
//! and implement anti-replay mitigation before using it.

use crate::{
    config,
    connection::Connection,
    error::{Error, Fallible, Pollable},
};
use s2n_tls_sys::*;
use std::task::Poll;

/// The status of early data (0-RTT) on a connection.
///
/// Corresponds to [`s2n_early_data_status_t`].
#[non_exhaustive]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum EarlyDataStatus {
    /// Early data is in progress.
    Ok,
    /// The client did not request early data, so none was sent or received.
    NotRequested,
    /// The client requested early data, but the server rejected the request.
    /// Early data may have been sent, but was not received.
    Rejected,
    /// All early data was successfully sent and received.
    End,
}

impl TryFrom<s2n_early_data_status_t::Type> for EarlyDataStatus {
    type Error = Error;

    fn try_from(input: s2n_early_data_status_t::Type) -> Result<Self, Self::Error> {
        let status = match input {
            s2n_early_data_status_t::OK => Self::Ok,
            s2n_early_data_status_t::NOT_REQUESTED => Self::NotRequested,
            s2n_early_data_status_t::REJECTED => Self::Rejected,
            s2n_early_data_status_t::END => Self::End,
            _ => return Err(Error::INVALID_INPUT),
        };
        Ok(status)
    }
}

impl Connection {
    /// Reports the current state of early data (0-RTT) for the connection.
    ///
    /// See [`EarlyDataStatus`] for all possible states.
    ///
    /// Corresponds to [`s2n_connection_get_early_data_status`].
    pub fn early_data_status(&self) -> Result<EarlyDataStatus, Error> {
        let mut status: s2n_early_data_status_t::Type = s2n_early_data_status_t::NOT_REQUESTED;
        unsafe {
            s2n_connection_get_early_data_status(self.as_ptr_shared(), &mut status)
                .into_result()?;
        }
        EarlyDataStatus::try_from(status)
    }

    /// Reports the remaining size of the early data allowed by the connection.
    ///
    /// If early data was rejected or not requested, the remaining early data size is 0.
    /// Otherwise, the remaining early data size is the maximum early data allowed by the
    /// connection, minus the early data sent or received so far.
    ///
    /// Corresponds to [`s2n_connection_get_remaining_early_data_size`].
    pub fn remaining_early_data_size(&self) -> Result<u32, Error> {
        let mut size = 0;
        unsafe {
            s2n_connection_get_remaining_early_data_size(self.as_ptr_shared(), &mut size)
                .into_result()?;
        }
        Ok(size)
    }

    /// Reports the maximum size of the early data allowed by the connection.
    ///
    /// This is the maximum amount of early data that can ever be sent and received for a
    /// connection. It is not affected by the actual status of the early data, so can be
    /// non-zero even if early data is rejected or not requested.
    ///
    /// Corresponds to [`s2n_connection_get_max_early_data_size`].
    pub fn max_early_data_size(&self) -> Result<u32, Error> {
        let mut size = 0;
        unsafe {
            s2n_connection_get_max_early_data_size(self.as_ptr_shared(), &mut size)
                .into_result()?;
        }
        Ok(size)
    }

    /// Begins negotiation and sends early data (0-RTT) as a client.
    ///
    /// Call this instead of [`Self::poll_negotiate`] to begin a handshake that offers early
    /// data; once it completes, call [`Self::poll_negotiate`] to finish the handshake.
    /// Requires session resumption or an external PSK configured for early data (see
    /// [`crate::psk::Builder::configure_early_data`]).
    ///
    /// Like [`Self::poll_send`], this is a partial-write API: `data` is the not-yet-sent
    /// slice and `sent` accumulates the bytes sent. On [`Poll::Pending`], call it again
    /// with the remainder (advance by `sent`); on `Poll::Ready(Ok(()))` all early data has
    /// been sent (or is no longer accepted), so call [`Self::poll_negotiate`] next. Do NOT
    /// re-pass bytes already reported as sent — s2n resends them as a second message.
    ///
    /// # Warning
    ///
    /// Early data is sent before the handshake completes, so it is not forward secret and
    /// is vulnerable to replay attacks. See the
    /// [early data usage guide](https://aws.github.io/s2n-tls/usage-guide/ch15-early-data.html)
    /// and implement anti-replay mitigation before using it.
    ///
    /// Corresponds to [`s2n_send_early_data`].
    pub fn poll_send_early_data(
        &mut self,
        data: &[u8],
        sent: &mut usize,
    ) -> Poll<Result<(), Error>> {
        let data_len: isize = data.len().try_into().map_err(|_| Error::INVALID_INPUT)?;
        // Drive through poll_negotiate_method for the same initializer trigger and
        // async-callback loop as poll_negotiate (e.g. so a ConnectionInitializer can load
        // a resumption ticket before the ClientHello). s2n reports this call's byte count
        // in data_sent (even when blocked) and resets it each call, so accumulate into
        // `sent` in the closure; poll_negotiate_method discards the closure's return value.
        self.poll_negotiate_method(|conn| {
            let mut blocked = s2n_blocked_status::NOT_BLOCKED;
            let mut data_sent: isize = 0;
            let result = unsafe {
                s2n_send_early_data(
                    conn.as_ptr(),
                    data.as_ptr(),
                    data_len,
                    &mut data_sent,
                    &mut blocked,
                )
                .into_poll()
            };
            *sent += data_sent as usize;
            result
        })
    }

    /// Begins negotiation and receives early data (0-RTT) as a server.
    ///
    /// Call this instead of [`Self::poll_negotiate`] to begin a handshake that accepts
    /// early data; once it completes, call [`Self::poll_negotiate`] to finish the
    /// handshake. Requires session resumption or an external PSK configured for early data
    /// (see [`crate::psk::Builder::configure_early_data`]).
    ///
    /// Like [`Self::poll_recv`], this is a partial-read API mirroring
    /// [`Self::poll_send_early_data`]: `buf` is the not-yet-filled remainder and `received`
    /// accumulates the bytes read. On [`Poll::Pending`], call it again with the remainder
    /// (advance by `received`); on `Poll::Ready(Ok(()))` all early data has been received,
    /// so call [`Self::poll_negotiate`] next. You must advance `buf` past bytes already
    /// received — s2n writes from offset 0 and would overwrite them.
    ///
    /// # Warning
    ///
    /// Early data is received before the handshake completes, so it is not forward secret
    /// and is vulnerable to replay attacks. See the
    /// [early data usage guide](https://aws.github.io/s2n-tls/usage-guide/ch15-early-data.html)
    /// and implement anti-replay mitigation before accepting it.
    ///
    /// Corresponds to [`s2n_recv_early_data`].
    pub fn poll_recv_early_data(
        &mut self,
        buf: &mut [u8],
        received: &mut usize,
    ) -> Poll<Result<(), Error>> {
        let max_len: isize = buf.len().try_into().map_err(|_| Error::INVALID_INPUT)?;
        let buf_ptr = buf.as_mut_ptr();
        // Drive through poll_negotiate_method for the same initializer trigger and
        // async-callback loop as poll_negotiate. s2n reports this call's byte count in
        // data_received (even when blocked) and resets it each call, so accumulate into
        // `received` in the closure; poll_negotiate_method discards the closure's return.
        self.poll_negotiate_method(move |conn| {
            let mut blocked = s2n_blocked_status::NOT_BLOCKED;
            let mut data_received: isize = 0;
            let result = unsafe {
                s2n_recv_early_data(
                    conn.as_ptr(),
                    buf_ptr,
                    max_len,
                    &mut data_received,
                    &mut blocked,
                )
                .into_poll()
            };
            *received += data_received as usize;
            result
        })
    }
}

impl config::Builder {
    /// Sets the maximum bytes of early data (0-RTT) the server will accept.
    ///
    /// The default is 0, meaning the server rejects all early data. A non-zero value lets
    /// the server accept early data from a resuming client: the limit is stored in the
    /// tickets it issues, so it must be set before the initial handshake. For external
    /// PSKs, use [`crate::psk::Builder::configure_early_data`] instead.
    ///
    /// Corresponds to [`s2n_config_set_server_max_early_data_size`].
    pub fn set_server_max_early_data_size(
        &mut self,
        max_early_data_size: u32,
    ) -> Result<&mut Self, Error> {
        unsafe {
            s2n_config_set_server_max_early_data_size(self.as_mut_ptr(), max_early_data_size)
                .into_result()
        }?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        enums::PskHmac,
        psk::Psk,
        security::DEFAULT_TLS13,
        testing::{build_config, TestPair},
    };

    const MAX_EARLY_DATA: u32 = 4096;
    // IANA value for TLS_AES_128_GCM_SHA256, which uses SHA256.
    const CIPHER_SUITE: [u8; 2] = [0x13, 0x01];

    /// Build a PSK configured for early data. The HMAC must match the cipher suite
    /// (SHA256 for TLS_AES_128_GCM_SHA256).
    fn early_data_psk() -> Psk {
        let mut builder = Psk::builder().unwrap();
        builder.set_identity(b"alice").unwrap();
        builder
            .set_secret(b"contrary to popular belief, the moon is yogurt, not cheese")
            .unwrap();
        builder.set_hmac(PskHmac::SHA256).unwrap();
        builder
            .configure_early_data(MAX_EARLY_DATA, CIPHER_SUITE)
            .unwrap();
        builder.build().unwrap()
    }

    /// A TLS 1.3 `TestPair` with the early-data PSK appended to both peers.
    fn early_data_pair() -> Result<TestPair, Error> {
        let psk = early_data_psk();
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        let mut pair = TestPair::from_config(&config.build()?);
        pair.client.append_psk(&psk)?;
        pair.server.append_psk(&psk)?;
        Ok(pair)
    }

    /// A full early-data exchange over a PSK: the client sends, the server receives, and
    /// both report `Ok` mid-handshake then `End` once it completes.
    #[test]
    fn psk_early_data_handshake() -> Result<(), Error> {
        const EARLY_DATA: &[u8] = b"hello 0-RTT world";
        let mut pair = early_data_pair()?;

        // Client sends the early data, then blocks waiting for the ServerHello.
        let mut sent = 0;
        assert!(pair
            .client
            .poll_send_early_data(EARLY_DATA, &mut sent)
            .is_pending());
        assert_eq!(sent, EARLY_DATA.len());
        assert_eq!(pair.client.early_data_status()?, EarlyDataStatus::Ok);

        // Server reads it, then blocks waiting for the client's end-of-early-data.
        let mut received = vec![0; EARLY_DATA.len()];
        let mut received_len = 0;
        assert!(pair
            .server
            .poll_recv_early_data(&mut received[received_len..], &mut received_len)
            .is_pending());
        assert_eq!(pair.server.early_data_status()?, EarlyDataStatus::Ok);
        assert_eq!(&received[..received_len], EARLY_DATA);

        // Complete the handshake; both sides end at `End`.
        pair.handshake()?;
        assert!(pair.client.handshake_complete());
        assert!(pair.server.handshake_complete());
        assert_eq!(pair.client.early_data_status()?, EarlyDataStatus::End);
        assert_eq!(pair.server.early_data_status()?, EarlyDataStatus::End);
        Ok(())
    }

    /// Regression test: re-polling `poll_send_early_data` with the not-yet-sent remainder
    /// (as the async driver does) must send the buffer exactly once. A driver that
    /// re-passed the full buffer or over-accumulated would send it twice, which this
    /// catches via `sent` and the consumed early-data budget.
    #[test]
    fn send_early_data_repoll_sends_once() -> Result<(), Error> {
        const EARLY_DATA: &[u8] = b"hello 0-RTT world";
        let mut pair = early_data_pair()?;

        // First call sends the whole buffer, then blocks on the ServerHello.
        let mut sent = 0;
        assert!(pair
            .client
            .poll_send_early_data(EARLY_DATA, &mut sent)
            .is_pending());
        assert_eq!(sent, EARLY_DATA.len());

        // Re-polling with the now-empty remainder must not resend.
        let _ = pair
            .client
            .poll_send_early_data(&EARLY_DATA[sent..], &mut sent);
        assert_eq!(sent, EARLY_DATA.len());
        assert_eq!(
            pair.client.remaining_early_data_size()?,
            MAX_EARLY_DATA - EARLY_DATA.len() as u32
        );
        Ok(())
    }

    /// Regression test: when early data arrives across more than one
    /// `poll_recv_early_data` call, each call must append into the not-yet-filled
    /// remainder and `received` must accumulate. Since s2n writes from offset 0, a caller
    /// that re-passed the full buffer would overwrite already-received data and lose it.
    #[test]
    fn recv_early_data_multicall_appends() -> Result<(), Error> {
        const CHUNK: &[u8] = b"0123456789";
        let mut pair = early_data_pair()?;

        let mut buf = vec![0u8; 1024];
        let mut received = 0;

        // Two separate records, each read by its own recv call. Re-passing the full CHUNK
        // with budget remaining sends a fresh record each time.
        for _ in 0..2 {
            let mut sent = 0;
            let _ = pair.client.poll_send_early_data(CHUNK, &mut sent);
            let _ = pair
                .server
                .poll_recv_early_data(&mut buf[received..], &mut received);
        }

        // Both records preserved back to back, with an accumulated count.
        assert_eq!(received, CHUNK.len() * 2);
        assert_eq!(&buf[..CHUNK.len()], CHUNK);
        assert_eq!(&buf[CHUNK.len()..received], CHUNK);
        Ok(())
    }

    /// `poll_send_early_data` must fail when called on a server connection.
    #[test]
    fn send_early_data_fails_on_server() -> Result<(), Error> {
        use core::task::Poll;

        let config = {
            let mut config = Config::builder();
            config.set_security_policy(&DEFAULT_TLS13)?;
            config.build()?
        };
        let mut pair = TestPair::from_config(&config);
        let mut sent = 0;
        match pair.server.poll_send_early_data(b"data", &mut sent) {
            Poll::Ready(Err(_)) => Ok(()),
            other => panic!("expected error on server, got {other:?}"),
        }
    }

    /// A fresh connection with no early data configured reports a max early data
    /// size of 0 and a `NotRequested` status after a normal handshake.
    #[test]
    fn no_early_data_configured() -> Result<(), Box<dyn std::error::Error>> {
        // Use a certificate-backed config so the handshake can complete without a PSK.
        let config = build_config(&DEFAULT_TLS13)?;
        let mut pair = TestPair::from_config(&config);
        assert_eq!(pair.client.max_early_data_size()?, 0);
        pair.handshake()?;
        assert_eq!(
            pair.client.early_data_status()?,
            EarlyDataStatus::NotRequested
        );
        Ok(())
    }
}
