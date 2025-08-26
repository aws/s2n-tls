// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    codec::{DecodeByteSource, DecodeValue},
    prefixed_list::{PrefixedBlob, PrefixedList},
};
use s2n_tls::error::Fallible;
use s2n_tls_sys::{s2n_client_hello_get_extension_by_id, s2n_client_hello_get_extension_length};
use std::ffi::c_uint;

trait S2NClientHelloExtension {
    /// retrieve the pre-shared-key extension from an s2n-tls client hello
    fn pre_shared_key(&self) -> Result<Option<Vec<u8>>, s2n_tls::error::Error>;
}

impl S2NClientHelloExtension for s2n_tls::client_hello::ClientHello {
    /// Retrieve the extension_data from the pre-shared-key extension
    fn pre_shared_key(&self) -> Result<Option<Vec<u8>>, s2n_tls::error::Error> {
        // we are depending on an internal implementation detail, where ClientHello
        // is aliased to the raw s2n_tls_sys type. Below is a compile-time assertion
        // that this hasn't changed. Even if the change isn't run through
        // aws-kms-tls-auth CI, customers will fail to build instead of
        // encountering a runtime error.
        static_assertions::assert_eq_size!(
            s2n_tls::client_hello::ClientHello,
            s2n_tls_sys::s2n_client_hello
        );

        // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
        const PRE_SHARED_KEY: c_uint = 41;

        let raw_ch =
            self as *const s2n_tls::client_hello::ClientHello as *mut s2n_tls_sys::s2n_client_hello;
        let psk_length =
            unsafe { s2n_client_hello_get_extension_length(raw_ch, PRE_SHARED_KEY).into_result() }?;
        if psk_length == 0 {
            return Ok(None);
        }

        let mut psk_extension = vec![0; psk_length];
        let written_length = unsafe {
            s2n_client_hello_get_extension_by_id(
                raw_ch,
                PRE_SHARED_KEY,
                psk_extension.as_mut_ptr(),
                psk_extension.len() as u32,
            )
            .into_result()
        }?;

        debug_assert_eq!(psk_length, written_length);

        Ok(Some(psk_extension))
    }
}

/// retrieve the PskIdentity items from the Psk extension in the ClientHello.
pub fn retrieve_psk_identities(
    client_hello: &s2n_tls::client_hello::ClientHello,
) -> anyhow::Result<PrefixedList<PskIdentity, u16>> {
    let psk_extension_data = match client_hello.pre_shared_key()? {
        Some(data) => data,
        None => anyhow::bail!("no psk extension found"),
    };
    let psk = PresharedKeyClientHello::decode_from_exact(&psk_extension_data)?;
    Ok(psk.identities)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PskIdentity {
    pub identity: PrefixedBlob<u16>,
    obfuscated_ticket_age: u32,
}

impl DecodeValue for PskIdentity {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (identity, buffer) = buffer.decode_value()?;
        let (obfuscated_ticket_age, buffer) = buffer.decode_value()?;

        let value = Self {
            identity,
            obfuscated_ticket_age,
        };

        Ok((value, buffer))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PskBinderEntry {
    entry: PrefixedBlob<u8>,
}

impl DecodeValue for PskBinderEntry {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (entry, buffer) = buffer.decode_value()?;

        let value = Self { entry };

        Ok((value, buffer))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresharedKeyClientHello {
    identities: PrefixedList<PskIdentity, u16>,
    binders: PrefixedList<PskBinderEntry, u16>,
}

impl DecodeValue for PresharedKeyClientHello {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (identities, buffer) = buffer.decode_value()?;
        let (binders, buffer) = buffer.decode_value()?;

        let value = Self {
            identities,
            binders,
        };

        Ok((value, buffer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use s2n_tls::{callbacks::VerifyHostNameCallback, enums::PskHmac, testing::TestPair};

    const PSK_IDENTITY: &[u8] = b"hello there imma psk";
    const PSK_SECRET: &[u8] = b"secret material for the psk";

    fn connection_with_psk() -> Result<s2n_tls::connection::Connection, s2n_tls::error::Error> {
        let mut config = s2n_tls::config::Config::builder();
        config.set_security_policy(&s2n_tls::security::DEFAULT_TLS13)?;
        let config = config.build()?;

        let psk = {
            let mut psk = s2n_tls::psk::Psk::builder()?;
            psk.set_hmac(PskHmac::SHA384)?;
            psk.set_identity(PSK_IDENTITY)?;
            psk.set_secret(PSK_SECRET)?;
            psk.build()?
        };

        let mut pair = TestPair::from_config(&config);
        pair.client.append_psk(&psk)?;
        pair.server.append_psk(&psk)?;

        pair.handshake()?;
        Ok(pair.server)
    }

    fn connection_without_psk() -> Result<s2n_tls::connection::Connection, s2n_tls::error::Error> {
        struct Verifier;
        impl VerifyHostNameCallback for Verifier {
            fn verify_host_name(&self, _host_name: &str) -> bool {
                true
            }
        }

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();

        let mut config = s2n_tls::config::Config::builder();
        config.set_security_policy(&s2n_tls::security::DEFAULT_TLS13)?;
        config.trust_pem(cert.pem().as_bytes())?;
        config.load_pem(
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )?;
        config.set_verify_host_callback(Verifier)?;
        let config = config.build()?;

        let mut pair = TestPair::from_config(&config);

        pair.handshake().unwrap();
        Ok(pair.server)
    }

    #[test]
    fn retrieve_identities() -> anyhow::Result<()> {
        let conn = connection_with_psk()?;
        let client_hello = conn.client_hello()?;
        let identities = retrieve_psk_identities(client_hello).unwrap();

        assert_eq!(identities.list().len(), 1);
        assert_eq!(identities.list()[0].identity.blob(), PSK_IDENTITY);
        Ok(())
    }

    #[test]
    fn no_available_identities() -> anyhow::Result<()> {
        let conn = connection_without_psk()?;
        let client_hello = conn.client_hello()?;
        let no_psk_error = retrieve_psk_identities(client_hello).unwrap_err();
        assert!(no_psk_error.to_string().contains("no psk extension found"));
        Ok(())
    }
}
