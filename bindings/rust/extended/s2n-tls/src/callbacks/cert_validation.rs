// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_sys::*;

use crate::{
    connection::Connection,
    error::{Error, Fallible},
};
use std::ptr::NonNull;

pub struct CertValidationInfo {
    info: NonNull<s2n_cert_validation_info>,
}

/// # Safety
///
/// Safety: s2n_cert_validation_info objects can be sent across threads
unsafe impl Send for CertValidationInfo {}

/// # Safety
///
/// Safety: All C methods that mutate the s2n_cert_validation_info are wrapped
/// in Rust methods that require a mutable reference.
unsafe impl Sync for CertValidationInfo {}

impl CertValidationInfo {
    pub(crate) fn from_ptr(info: *mut s2n_cert_validation_info) -> Result<Self, Error> {
        let info = NonNull::new(info).ok_or(Error::INVALID_INPUT)?;
        Ok(CertValidationInfo { info })
    }

    pub(crate) fn as_ptr(&self) -> *mut s2n_cert_validation_info {
        self.info.as_ptr()
    }

    /// Corresponds to [s2n_cert_validation_accept].
    pub fn accept(self) -> Result<(), Error> {
        unsafe { s2n_cert_validation_accept(self.as_ptr()).into_result() }?;
        Ok(())
    }

    /// Corresponds to [s2n_cert_validation_reject].
    pub fn reject(self) -> Result<(), Error> {
        unsafe { s2n_cert_validation_reject(self.as_ptr()).into_result() }?;
        Ok(())
    }
}

pub trait CertValidationCallback: 'static + Send + Sync {
    fn handle_validation(
        &self,
        connection: &mut Connection,
        validation_info: CertValidationInfo,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{connection::Connection, security, testing::*};

    type Error = Box<dyn std::error::Error>;

    struct ValidationContext {
        accept: bool,
    }

    struct SyncCallback(Counter);
    impl CertValidationCallback for SyncCallback {
        fn handle_validation(
            &self,
            conn: &mut Connection,
            info: CertValidationInfo,
        ) -> Result<(), Error> {
            self.0.increment();
            let context = conn.application_context::<ValidationContext>().unwrap();

            match context.accept {
                true => info.accept()?,
                false => info.reject()?,
            }
            Ok(())
        }
    }

    #[test]
    fn sync_cert_validation() -> Result<(), Error> {
        for accept in [true, false] {
            let counter = Counter::default();
            let callback = SyncCallback(counter.clone());

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
