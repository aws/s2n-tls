// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_sys::*;

use crate::{
    connection::Connection,
    error::{Error, Fallible},
};
use std::{marker::PhantomData, ptr::NonNull};

pub struct CertValidationInfo<'a> {
    pub info: NonNull<s2n_cert_validation_info>,
    _lifetime: PhantomData<&'a s2n_cert_validation_info>,
}

impl CertValidationInfo<'_> {
    pub fn from_ptr(info: *mut s2n_cert_validation_info) -> Self {
        let info = NonNull::new(info).expect("info pointer should not be null");
        CertValidationInfo {
            info,
            _lifetime: PhantomData,
        }
    }

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

pub trait CertValidationCallbackSync: 'static + Send + Sync {
    /// Return a boolean to indicate if the certificate chain passed the validation
    fn handle_validation(
        &self,
        connection: &mut Connection,
        validation_info: &mut CertValidationInfo,
    ) -> Result<bool, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{connection::Connection, security, testing::*};

    struct ValidationContext {
        accept: bool,
    }

    struct SyncCallback(Counter);
    impl CertValidationCallbackSync for SyncCallback {
        fn handle_validation(
            &self,
            conn: &mut Connection,
            _info: &mut CertValidationInfo,
        ) -> Result<bool, Error> {
            self.0.increment();
            let context = conn.application_context::<ValidationContext>().unwrap();
            Ok(context.accept)
        }
    }

    #[test]
    fn sync_cert_validation() -> Result<(), Box<dyn std::error::Error>> {
        for accept in [true, false] {
            let counter = Counter::default();
            let callback = SyncCallback(counter.clone());

            let config = {
                let mut config = config_builder(&security::DEFAULT_TLS13)?;
                config.set_cert_validation_callback_sync(callback)?;
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
