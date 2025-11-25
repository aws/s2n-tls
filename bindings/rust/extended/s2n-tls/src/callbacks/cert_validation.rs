// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_sys::*;

use crate::{
    connection::Connection,
    error::{Error, Fallible},
};
use std::{marker::PhantomData, ptr::NonNull};

pub struct CertValidationInfo<'a> {
    info: NonNull<s2n_cert_validation_info>,
    _lifetime: PhantomData<&'a s2n_cert_validation_info>,
}

impl CertValidationInfo<'_> {
    /// Creates a `CertValidationInfo` from a raw pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `info` is a non-null pointer to a valid `s2n_cert_validation_info` structure
    /// - The pointed-to structure is owned by s2n-tls and remains valid for the lifetime
    ///   of this `CertValidationInfo` (typically until the handshake completes or the
    ///   connection is freed)
    /// - The pointer is not used to create multiple mutable references
    pub unsafe fn from_ptr(info: *mut s2n_cert_validation_info) -> Self {
        let info = NonNull::new(info).expect("info pointer should not be null");
        CertValidationInfo {
            info,
            _lifetime: PhantomData,
        }
    }

    /// Returns the raw pointer to the underlying `s2n_cert_validation_info`.
    ///
    /// This is primarily useful for passing to FFI functions or storing for later use.
    pub fn as_ptr(&mut self) -> *mut s2n_cert_validation_info {
        self.info.as_ptr()
    }

    /// Corresponds to [s2n_cert_validation_accept].
    pub fn accept(&mut self) -> Result<(), Error> {
        unsafe { s2n_cert_validation_accept(self.as_ptr()).into_result() }?;
        Ok(())
    }

    /// Corresponds to [s2n_cert_validation_reject].
    pub fn reject(&mut self) -> Result<(), Error> {
        unsafe { s2n_cert_validation_reject(self.as_ptr()).into_result() }?;
        Ok(())
    }
}

/// Certificate validation callback that supports both synchronous and asynchronous validation.
///
/// The callback can operate in three modes based on the return value:
/// - `Ok(Some(true))`: Accept the certificate immediately (synchronous)
/// - `Ok(Some(false))`: Reject the certificate immediately (synchronous)
/// - `Ok(None)`: Defer the decision (asynchronous) - the application must call
///   `validation_info.accept()` or `validation_info.reject()` later
///
/// When returning `None`, the handshake will block (return S2N_ERR_T_BLOCKED with
/// S2N_BLOCKED_ON_APPLICATION_INPUT) until validation is completed by calling
/// `accept()` or `reject()` on the validation info.
///
pub trait CertValidationCallback: 'static + Send + Sync {
    /// Validate the certificate chain.
    ///
    /// Return:
    /// - `Some(true)` to accept immediately
    /// - `Some(false)` to reject immediately
    /// - `None` to defer the decision (async mode)
    fn handle_validation(
        &self,
        connection: &mut Connection,
        validation_info: &mut CertValidationInfo,
    ) -> Result<Option<bool>, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{connection::Connection, security, testing::*};

    struct ValidationContext {
        accept: bool,
    }

    struct TestCallback(Counter);
    impl CertValidationCallback for TestCallback {
        fn handle_validation(
            &self,
            conn: &mut Connection,
            _info: &mut CertValidationInfo,
        ) -> Result<Option<bool>, Error> {
            self.0.increment();
            let context = conn.application_context::<ValidationContext>().unwrap();
            // Return Some(accept) for synchronous validation
            Ok(Some(context.accept))
        }
    }

    #[test]
    fn sync_cert_validation() -> Result<(), Box<dyn std::error::Error>> {
        for accept in [true, false] {
            let counter = Counter::default();
            let callback = TestCallback(counter.clone());

            let config = {
                let mut config = config_builder(&security::DEFAULT_TLS13)?;
                config.set_cert_validation_callback(callback)?;
                config.build()?
            };

            let mut pair = TestPair::from_config(&config);
            let context = ValidationContext { accept };
            pair.client.set_application_context(context);

            assert_eq!(counter.count(), 0);

            if accept {
                pair.handshake()?;
            } else {
                let s2n_err = pair.handshake().unwrap_err();
                assert_eq!(s2n_err.name(), "S2N_ERR_CERT_REJECTED");
            }

            assert_eq!(counter.count(), 1);
        }

        Ok(())
    }
}
