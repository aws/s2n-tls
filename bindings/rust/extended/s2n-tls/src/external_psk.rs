// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    enums::PskHmac,
    error::{Error, ErrorType, Fallible},
};
use s2n_tls_sys::*;

/// TODO: document builder items
/// TODO: I still need the visibility
///       because list ref needs to be pub crate

#[derive(Debug)]
pub struct Builder {
    psk: ExternalPsk,
    has_identity: bool,
    has_secret: bool,
    has_hmac: bool,
}

impl Builder {
    pub fn new() -> Result<Self, crate::error::Error> {
        crate::init::init();
        let psk = ExternalPsk::allocate()?;
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
    pub fn with_identity(&mut self, identity: &[u8]) -> Result<&mut Self, crate::error::Error> {
        let identity_length = identity.len().try_into().map_err(|_| {
            Error::bindings(
                ErrorType::UsageError,
                "invalid psk identity",
                "The identity must be no longer than u16::MAX",
            )
        })?;
        unsafe {
            s2n_psk_set_identity(
                self.psk.as_s2n_ptr_mut(),
                identity.as_ptr(),
                identity_length,
            )
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
    pub fn with_secret(&mut self, secret: &[u8]) -> Result<&mut Self, crate::error::Error> {
        let secret_length = secret.len().try_into().map_err(|_| {
            Error::bindings(
                ErrorType::UsageError,
                "invalid psk secret",
                "The secret must be no longer than u16::MAX",
            )
        })?;

        // These checks would ideally be in the C code, but would be a backwards
        // incompatible change.
        //= https://www.rfc-editor.org/rfc/rfc9257.html#section-6
        //# Each PSK ... MUST be at least 128 bits long
        if secret_length < (128 / 8) {
            return Err(Error::bindings(
                ErrorType::UsageError,
                "invalid psk secret",
                "PSK secret must be at least 128 bits",
            ));
        }
        // There are a number of application level errors that might result in an
        // all-zero secret accidentally getting used. Error if that happens.
        if secret.iter().all(|b| *b == 0) {
            return Err(Error::bindings(
                ErrorType::UsageError,
                "invalid psk secret",
                "PSK secret must not be all zeros",
            ));
        }
        unsafe {
            s2n_psk_set_secret(self.psk.as_s2n_ptr_mut(), secret.as_ptr(), secret_length)
                .into_result()
        }?;
        self.has_secret = true;
        Ok(self)
    }

    /// Set the HMAC function associated with the PSK.
    ///
    /// Corresponds to [`s2n_psk_set_hmac`].
    pub fn with_hmac(&mut self, hmac: PskHmac) -> Result<&mut Self, crate::error::Error> {
        unsafe { s2n_psk_set_hmac(self.psk.as_s2n_ptr_mut(), hmac.into()).into_result() }?;
        self.has_hmac = true;
        Ok(self)
    }

    pub fn build(self) -> Result<ExternalPsk, crate::error::Error> {
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

crate::foreign_types::define_owned_type!(
    /// ExternalPsk represents an out-of-band pre-shared key.
    ///
    /// If two peers already have some mechanism to securely exchange secrets, then
    /// they can use ExternalPSKs to authenticate rather than certificates.
    pub ExternalPsk,
    s2n_psk
);

/// # Safety
///
/// Safety: ExternalPsk objects can be sent across threads
unsafe impl Send for ExternalPsk {}

/// # Safety
///
/// Safety: There are no methods that mutate the ExternalPsk.
unsafe impl Sync for ExternalPsk {}

impl ExternalPsk {
    fn allocate() -> Result<Self, crate::error::Error> {
        let psk = unsafe { s2n_external_psk_new().into_result() }?;
        Ok(Self { ptr: psk })
    }

    pub fn builder() -> Result<Builder, crate::error::Error> {
        Builder::new()
    }
}

impl Drop for ExternalPsk {
    fn drop(&mut self) {
        // ignore failures. There isn't anything to be done to handle them, but
        // allowing the program to continue is preferable to crashing.
        let _ = unsafe { s2n_psk_free(&mut self.as_s2n_ptr_mut()).into_result() };
    }
}

#[cfg(test)]
mod tests {
    use crate::{config::Config, error::ErrorSource, security::DEFAULT_TLS13, testing::TestPair};

    use super::*;

    #[test]
    /// `identity`, `secret`, and `hmac` are all required fields. If any of them
    /// aren't set, then `psk.build()` operation should fail.
    fn build_errors() -> Result<(), crate::error::Error> {
        const PERMUTATIONS: u8 = 0b111;

        for permutation in 0..PERMUTATIONS {
            let mut psk = Builder::new()?;
            if permutation & 0b001 != 0 {
                psk.with_identity(b"Alice")?;
            }
            if permutation & 0b010 != 0 {
                psk.with_secret(b"Rabbits don't actually jump. They instead push the world down")?;
            }
            if permutation & 0b100 != 0 {
                psk.with_hmac(PskHmac::SHA384)?;
            }
            assert!(psk.build().is_err());
        }
        Ok(())
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9257.html#section-6
    //= type=test
    //# Each PSK ... MUST be at least 128 bits long
    fn psk_secret_must_be_at_least_128_bits() -> Result<(), crate::error::Error> {
        // 120 bit key
        let secret = vec![5; 15];

        let mut psk = Builder::new()?;
        let err = psk.with_secret(&secret).unwrap_err();
        assert_eq!(err.source(), ErrorSource::Bindings);
        assert_eq!(err.kind(), ErrorType::UsageError);
        assert_eq!(err.name(), "invalid psk secret");
        assert_eq!(err.message(), "PSK secret must be at least 128 bits");
        Ok(())
    }

    const TEST_PSK_IDENTITY: &[u8] = b"alice";

    fn test_psk() -> ExternalPsk {
        let mut builder = ExternalPsk::builder().unwrap();
        builder.with_identity(TEST_PSK_IDENTITY).unwrap();
        builder
            .with_secret(b"contrary to popular belief, the moon is yogurt, not cheese")
            .unwrap();
        builder.with_hmac(PskHmac::SHA384).unwrap();
        builder.build().unwrap()
    }

    #[test]
    /// A PSK handshake using the basic "append_psk" workflow should complete
    /// successfully, and the correct negotiated psk identity should be returned.
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
