// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ptr::NonNull;

use crate::{
    enums::PskHmac,
    error::{Error, ErrorType, Fallible},
};
use s2n_tls_sys::*;

#[derive(Debug)]
pub struct Builder {
    psk: Psk,
    has_identity: bool,
    has_secret: bool,
    has_hmac: bool,
}

impl Builder {
    pub fn new() -> Result<Self, crate::error::Error> {
        crate::init::init();
        let psk = Psk::allocate()?;
        Ok(Self {
            psk,
            has_identity: false,
            has_secret: false,
            has_hmac: false,
        })
    }

    /// Set the public PSK identity.
    ///
    /// Corresponds to [`s2n_psk_set_identity`].
    pub fn set_identity(&mut self, identity: &[u8]) -> Result<&mut Self, crate::error::Error> {
        let identity_length = identity.len().try_into().map_err(|_| {
            Error::bindings(
                ErrorType::UsageError,
                "invalid psk identity",
                "The identity must be no longer than u16::MAX",
            )
        })?;
        unsafe {
            s2n_psk_set_identity(self.psk.ptr.as_ptr(), identity.as_ptr(), identity_length)
                .into_result()
        }?;
        self.has_identity = true;
        Ok(self)
    }

    /// Set the PSK secret.
    ///
    /// Secrets must be at least 16 bytes.
    ///
    /// Corresponds to [`s2n_psk_set_secret`].
    pub fn set_secret(&mut self, secret: &[u8]) -> Result<&mut Self, crate::error::Error> {
        let secret_length = secret.len().try_into().map_err(|_| {
            Error::bindings(
                ErrorType::UsageError,
                "invalid psk secret",
                "The secret must be no longer than u16::MAX",
            )
        })?;

        // These checks are only in the Rust code. Adding them to C would be a
        // backwards incompatible change.
        //= https://www.rfc-editor.org/rfc/rfc9257.html#section-6
        //# Each PSK ... MUST be at least 128 bits long
        if secret_length < (128 / 8) {
            return Err(Error::bindings(
                ErrorType::UsageError,
                "invalid psk secret",
                "PSK secret must be at least 128 bits",
            ));
        }
        unsafe {
            s2n_psk_set_secret(self.psk.ptr.as_ptr(), secret.as_ptr(), secret_length).into_result()
        }?;
        self.has_secret = true;
        Ok(self)
    }

    /// Set the HMAC function associated with the PSK.
    ///
    /// Corresponds to [`s2n_psk_set_hmac`].
    pub fn set_hmac(&mut self, hmac: PskHmac) -> Result<&mut Self, crate::error::Error> {
        unsafe { s2n_psk_set_hmac(self.psk.ptr.as_ptr(), hmac.into()).into_result() }?;
        self.has_hmac = true;
        Ok(self)
    }

    /// Configures this pre-shared key to allow early data (0-RTT).
    ///
    /// `max_early_data_size` must be set to the maximum early data accepted by the server.
    ///
    /// In order to use early data, the cipher suite set on the pre-shared key must match the
    /// cipher suite ultimately negotiated by the TLS handshake. Additionally, the cipher suite
    /// must have the same HMAC algorithm as the pre-shared key. `cipher_suite` is the two
    /// bytes of the suite's registered IANA value (e.g. `[0x13, 0x01]` for
    /// `TLS_AES_128_GCM_SHA256`).
    ///
    /// Corresponds to [`s2n_psk_configure_early_data`].
    pub fn configure_early_data(
        &mut self,
        max_early_data_size: u32,
        cipher_suite: [u8; 2],
    ) -> Result<&mut Self, crate::error::Error> {
        unsafe {
            s2n_psk_configure_early_data(
                self.psk.ptr.as_ptr(),
                max_early_data_size,
                cipher_suite[0],
                cipher_suite[1],
            )
            .into_result()
        }?;
        Ok(self)
    }

    /// Sets the optional application protocol associated with this pre-shared key.
    ///
    /// In order to use early data, the application protocol set on the pre-shared key must
    /// match the application protocol ultimately negotiated by the TLS handshake.
    ///
    /// Corresponds to [`s2n_psk_set_application_protocol`].
    pub fn set_application_protocol(
        &mut self,
        protocol: &[u8],
    ) -> Result<&mut Self, crate::error::Error> {
        let protocol_length = protocol.len().try_into().map_err(|_| {
            Error::bindings(
                ErrorType::UsageError,
                "invalid application protocol",
                "The application protocol must be no longer than u8::MAX",
            )
        })?;
        unsafe {
            s2n_psk_set_application_protocol(
                self.psk.ptr.as_ptr(),
                protocol.as_ptr(),
                protocol_length,
            )
            .into_result()
        }?;
        Ok(self)
    }

    pub fn build(self) -> Result<Psk, crate::error::Error> {
        if !self.has_identity {
            Err(Error::bindings(
                crate::error::ErrorType::UsageError,
                "invalid psk",
                "You must set an identity using `with_identity`",
            ))
        } else if !self.has_secret {
            Err(Error::bindings(
                crate::error::ErrorType::UsageError,
                "invalid psk",
                "You must set a secret using `with_secret`",
            ))
        } else if !self.has_hmac {
            Err(Error::bindings(
                crate::error::ErrorType::UsageError,
                "invalid psk",
                "You must set an hmac `with_hmac`",
            ))
        } else {
            Ok(self.psk)
        }
    }
}

/// Psk represents an out-of-band pre-shared key.
///
/// If two peers already have some mechanism to securely exchange secrets, then
/// they can use Psks to authenticate rather than certificates.
#[derive(Debug)]
pub struct Psk {
    // SAFETY: `ptr.as_ptr()` allows a `*mut s2n_psk` to be returned from `&Psk`.
    // This is required because all s2n-tls C psk APIs take a mutable pointer.
    // This is only safe if the `*mut s2n_psk` from `&Psk` is still treated as
    // logically const by the s2n-tls C library.
    pub(crate) ptr: NonNull<s2n_psk>,
}

/// # Safety
///
/// Safety: Psk objects can be sent across threads
unsafe impl Send for Psk {}

/// # Safety
///
/// Safety: There are no methods that mutate the Psk through a shared reference
/// (i.e., no interior mutability is exposed)
unsafe impl Sync for Psk {}

impl Psk {
    /// Allocate a new, uninitialized Psk.
    ///
    /// Corresponds to [`s2n_external_psk_new`].
    fn allocate() -> Result<Self, crate::error::Error> {
        let psk = unsafe { s2n_external_psk_new().into_result() }?;
        Ok(Self { ptr: psk })
    }

    pub fn builder() -> Result<Builder, crate::error::Error> {
        Builder::new()
    }
}

impl Drop for Psk {
    /// Corresponds to [`s2n_psk_free`].
    fn drop(&mut self) {
        // ignore failures. There isn't anything to be done to handle them, but
        // allowing the program to continue is preferable to crashing.
        let _ = unsafe { s2n_psk_free(&mut self.ptr.as_ptr()).into_result() };
    }
}

#[cfg(test)]
mod tests {
    use crate::{config::Config, error::ErrorSource, security::DEFAULT_TLS13, testing::TestPair};

    use super::*;

    /// `identity`, `secret`, and `hmac` are all required fields. If any of them
    /// aren't set, then `psk.build()` operation should fail.
    #[test]
    fn build_errors() -> Result<(), crate::error::Error> {
        const PERMUTATIONS: u8 = 0b111;

        for permutation in 0..PERMUTATIONS {
            let mut psk = Builder::new()?;
            if permutation & 0b001 != 0 {
                psk.set_identity(b"Alice")?;
            }
            if permutation & 0b010 != 0 {
                psk.set_secret(b"Rabbits don't actually jump. They instead push the world down")?;
            }
            if permutation & 0b100 != 0 {
                psk.set_hmac(PskHmac::SHA384)?;
            }
            assert!(psk.build().is_err());
        }
        Ok(())
    }

    //= https://www.rfc-editor.org/rfc/rfc9257.html#section-6
    //= type=test
    //# Each PSK ... MUST be at least 128 bits long
    #[test]
    fn psk_secret_must_be_at_least_128_bits() -> Result<(), crate::error::Error> {
        // 120 bit key
        let secret = vec![5; 15];

        let mut psk = Builder::new()?;
        let err = psk.set_secret(&secret).unwrap_err();
        assert_eq!(err.source(), ErrorSource::Bindings);
        assert_eq!(err.kind(), ErrorType::UsageError);
        assert_eq!(err.name(), "invalid psk secret");
        assert_eq!(err.message(), "PSK secret must be at least 128 bits");
        Ok(())
    }

    const TEST_PSK_IDENTITY: &[u8] = b"alice";

    fn test_psk() -> Psk {
        let mut builder = Psk::builder().unwrap();
        builder.set_identity(TEST_PSK_IDENTITY).unwrap();
        builder
            .set_secret(b"contrary to popular belief, the moon is yogurt, not cheese")
            .unwrap();
        builder.set_hmac(PskHmac::SHA384).unwrap();
        builder.build().unwrap()
    }

    /// A PSK handshake using the basic "append_psk" workflow should complete
    /// successfully, and the correct negotiated psk identity should be returned.
    #[test]
    fn psk_handshake() -> Result<(), crate::error::Error> {
        let psk = test_psk();
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        let config = config.build()?;
        let mut test_pair = TestPair::from_config(&config);
        test_pair.client.append_psk(&psk)?;
        test_pair.server.append_psk(&psk)?;
        assert!(test_pair.handshake().is_ok());

        for peer in [test_pair.client, test_pair.server] {
            let mut identity_buffer = [0; TEST_PSK_IDENTITY.len()];
            assert_eq!(
                peer.negotiated_psk_identity_length()?,
                TEST_PSK_IDENTITY.len()
            );
            peer.negotiated_psk_identity(&mut identity_buffer)?;
            assert_eq!(identity_buffer, TEST_PSK_IDENTITY);
        }
        Ok(())
    }

    const MAX_EARLY_DATA: u32 = 4096;
    // IANA value for TLS_AES_128_GCM_SHA256, which uses SHA256.
    const CIPHER_SUITE: [u8; 2] = [0x13, 0x01];

    /// Build a PSK configured for early data. The HMAC must match the cipher suite
    /// (SHA256 for TLS_AES_128_GCM_SHA256).
    fn early_data_psk() -> Psk {
        let mut builder = Psk::builder().unwrap();
        builder.set_identity(TEST_PSK_IDENTITY).unwrap();
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
    fn early_data_pair() -> Result<TestPair, crate::error::Error> {
        let psk = early_data_psk();
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        let mut pair = TestPair::from_config(&config.build()?);
        pair.client.append_psk(&psk)?;
        pair.server.append_psk(&psk)?;
        Ok(pair)
    }

    /// A client using `poll_send_early_data` with an early-data-enabled PSK should
    /// successfully send early data that the server receives, and both sides should
    /// report an `End` early data status after the handshake completes.
    #[test]
    fn psk_early_data_handshake() -> Result<(), crate::error::Error> {
        use crate::enums::EarlyDataStatus;

        const EARLY_DATA: &[u8] = b"hello 0-RTT world";

        let mut pair = early_data_pair()?;

        // Step 1: client sends early data. This writes the ClientHello and early
        // data records into the shared buffer, then blocks waiting for the server's
        // ServerHello. The early data is sent even though the call reports Pending.
        let mut sent = 0;
        let send = pair.client.poll_send_early_data(EARLY_DATA, &mut sent);
        assert!(
            send.is_pending(),
            "client should block waiting for ServerHello"
        );
        // The early data is buffered/sent even though the handshake is not complete.
        assert_eq!(sent, EARLY_DATA.len());
        assert_eq!(pair.client.early_data_status()?, EarlyDataStatus::Ok);

        // Step 2: server receives the early data. It reads the ClientHello and early
        // data, then blocks waiting for the client's EndOfEarlyData/Finished.
        let mut received = vec![0; EARLY_DATA.len()];
        let mut received_len = 0;
        let recv = pair
            .server
            .poll_recv_early_data(&mut received[received_len..], &mut received_len);
        assert!(
            recv.is_pending(),
            "server should block waiting for end of early data"
        );
        assert_eq!(pair.server.early_data_status()?, EarlyDataStatus::Ok);
        assert_eq!(&received[..received_len], EARLY_DATA);

        // Step 3: complete the handshake on both sides. poll_negotiate sends the
        // EndOfEarlyData message and finishes.
        pair.handshake()?;

        assert!(pair.client.handshake_complete());
        assert!(pair.server.handshake_complete());
        assert_eq!(pair.client.early_data_status()?, EarlyDataStatus::End);
        assert_eq!(pair.server.early_data_status()?, EarlyDataStatus::End);
        Ok(())
    }

    /// Regression test: re-polling `poll_send_early_data` with the not-yet-sent remainder
    /// (as the async driver does) must send the buffer exactly once and report `sent`
    /// exactly once. A driver that re-passed the full buffer or over-accumulated would
    /// send the early data twice, which this catches via the consumed early-data budget.
    #[test]
    fn send_early_data_repoll_sends_once() -> Result<(), crate::error::Error> {
        use crate::enums::EarlyDataStatus;
        use core::task::Poll;

        const EARLY_DATA: &[u8] = b"hello 0-RTT world";

        let mut pair = early_data_pair()?;

        // Prime the server to accept early data (sets early_data_expected), then drive the
        // client's send phase like the async driver: re-poll until Ready(Ok), pumping the
        // server between polls.
        let mut server_buf = vec![0; EARLY_DATA.len() * 4];
        let mut server_received = 0;
        let _ = pair
            .server
            .poll_recv_early_data(&mut server_buf[server_received..], &mut server_received);

        let mut sent = 0;
        for attempt in 0..16 {
            // Pass the not-yet-sent remainder, matching the async driver's contract.
            match pair
                .client
                .poll_send_early_data(&EARLY_DATA[sent..], &mut sent)
            {
                Poll::Ready(Ok(())) => break,
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Pending => {
                    let _ = pair.server.poll_recv_early_data(
                        &mut server_buf[server_received..],
                        &mut server_received,
                    );
                }
            }
            assert!(attempt < 15, "send-early-data phase did not converge");
        }

        // Must report exactly one buffer's worth, never a multiple of it.
        assert_eq!(sent, EARLY_DATA.len());
        // Budget consumed must be exactly one buffer. A double-send would consume 2x.
        assert_eq!(
            pair.client.remaining_early_data_size()?,
            MAX_EARLY_DATA - EARLY_DATA.len() as u32
        );

        // The server must receive exactly the payload, once.
        let _ = pair
            .server
            .poll_recv_early_data(&mut server_buf[server_received..], &mut server_received);
        assert_eq!(server_received, EARLY_DATA.len());
        assert_eq!(&server_buf[..server_received], EARLY_DATA);

        pair.handshake()?;
        assert_eq!(pair.client.early_data_status()?, EarlyDataStatus::End);
        assert_eq!(pair.server.early_data_status()?, EarlyDataStatus::End);
        Ok(())
    }

    /// Regression test: when early data arrives across more than one
    /// `poll_recv_early_data` call, each call must append into the not-yet-filled
    /// remainder and `received` must accumulate. Since s2n writes from offset 0, a caller
    /// that re-passed the full buffer would overwrite already-received data and lose it.
    #[test]
    fn recv_early_data_multicall_appends() -> Result<(), crate::error::Error> {
        const CHUNK: &[u8] = b"0123456789";

        let mut pair = early_data_pair()?;

        let mut buf = vec![0u8; 1024];
        let mut received = 0;

        // Two separate early-data records, each read by its own recv call. Re-passing the
        // full CHUNK to poll_send_early_data with budget remaining sends a fresh record.
        for _ in 0..2 {
            let mut sent = 0;
            let _ = pair.client.poll_send_early_data(CHUNK, &mut sent);
            let _ = pair
                .server
                .poll_recv_early_data(&mut buf[received..], &mut received);
        }

        // Both records must be preserved, back to back, with an accumulated count.
        assert_eq!(received, CHUNK.len() * 2);
        assert_eq!(&buf[..CHUNK.len()], CHUNK);
        assert_eq!(&buf[CHUNK.len()..received], CHUNK);
        Ok(())
    }

    /// `poll_send_early_data` must fail when called on a server connection.
    #[test]
    fn send_early_data_fails_on_server() -> Result<(), crate::error::Error> {
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
        use crate::enums::EarlyDataStatus;

        // Use a certificate-backed config so the handshake can complete without a PSK.
        let config = crate::testing::build_config(&DEFAULT_TLS13)?;
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
