// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_sys::*;

use crate::{
    connection::Connection,
    error::{Error, Fallible},
};

pub struct CertValidationInfo(s2n_cert_validation_info);

impl CertValidationInfo {
    pub(crate) fn from_ptr(info: *mut s2n_cert_validation_info) -> &'static mut Self {
        unsafe { &mut *(info as *mut CertValidationInfo) }
    }

    pub(crate) fn as_ptr(&mut self) -> *mut s2n_cert_validation_info {
        &self.0 as *const s2n_cert_validation_info as *mut s2n_cert_validation_info
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
    fn handle_validation(
        &self,
        connection: &mut Connection,
        validation_info: &mut CertValidationInfo,
    ) -> Result<(), Error>;
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
            info: &mut CertValidationInfo,
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
