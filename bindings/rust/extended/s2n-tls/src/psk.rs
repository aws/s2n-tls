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
    /// Corresponds to [s2n_psk_set_identity].
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
    /// Corresponds to [s2n_psk_set_secret].
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
    /// Corresponds to [s2n_psk_set_hmac].
    pub fn set_hmac(&mut self, hmac: PskHmac) -> Result<&mut Self, crate::error::Error> {
        unsafe { s2n_psk_set_hmac(self.psk.ptr.as_ptr(), hmac.into()).into_result() }?;
        self.has_hmac = true;
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
    /// Corresponds to [s2n_external_psk_new].
    fn allocate() -> Result<Self, crate::error::Error> {
        let psk = unsafe { s2n_external_psk_new().into_result() }?;
        Ok(Self { ptr: psk })
    }

    pub fn builder() -> Result<Builder, crate::error::Error> {
        Builder::new()
    }
}

impl Drop for Psk {
    /// Corresponds to [s2n_psk_free].
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
}
