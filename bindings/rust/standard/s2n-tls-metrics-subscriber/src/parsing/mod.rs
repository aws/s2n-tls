// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module holds the parsing logic that we need to pull interesting bits out
//! of the client hello

use std::ffi::c_uint;

use s2n_codec::DecoderBuffer;
use s2n_tls::{client_hello::ClientHello as S2NClientHello, error::Fallible};
use s2n_tls_sys::{s2n_client_hello_get_extension_by_id, s2n_client_hello_get_extension_length};

use crate::{
    parsing::messages::{
        ClientHello, SignatureSchemeList, SupportedGroups, SupportedVersionsClientHello,
    },
    static_lists::{Cipher, Group, Signature, Version},
};

mod messages;

/// This struct provides utility methods to access the supported parameters from
/// a client hello
pub struct ClientHelloSupportedParameters<'a> {
    client_hello: &'a S2NClientHello,
}

impl<'a> ClientHelloSupportedParameters<'a> {
    /// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
    const SUPPORTED_GROUPS_ID: u16 = 10;
    const SUPPORTED_VERSIONS_ID: u16 = 43;
    const SIGNATURE_ALGORITHMS_ID: u16 = 13;

    /// the raw bytes of the client hello message.
    ///
    /// This must not include the message header.
    pub fn new(client_hello: &'a S2NClientHello) -> Self {
        Self { client_hello }
    }

    // s2n-tls doesn't offer any way to extract the offered ciphers from the
    // client hello, so we do it manually.
    pub fn supported_ciphers(&self) -> Result<Vec<Cipher>, Box<dyn std::error::Error>> {
        let bytes = self.client_hello.raw_message()?;
        let buffer = DecoderBuffer::new(bytes.as_ref());
        let client_hello = buffer.decode_exact::<ClientHello>()?;
        Ok(client_hello.cipher_suites.list.to_vec())
    }

    pub fn supported_groups(&self) -> Result<Option<Vec<Group>>, Box<dyn std::error::Error>> {
        let bytes = self.client_hello.get_extension(Self::SUPPORTED_GROUPS_ID)?;
        let groups = match bytes {
            Some(buffer) => {
                let buffer = DecoderBuffer::new(&buffer);
                let supported_groups = buffer.decode_exact::<SupportedGroups>()?;
                supported_groups.named_group_list.list.to_vec()
            }
            None => return Ok(None),
        };
        Ok(Some(groups))
    }

    pub fn supported_signatures(
        &self,
    ) -> Result<Option<Vec<Signature>>, Box<dyn std::error::Error>> {
        let bytes = self
            .client_hello
            .get_extension(Self::SIGNATURE_ALGORITHMS_ID)?;
        let sigs = match bytes {
            Some(buffer) => {
                let buffer = DecoderBuffer::new(&buffer);
                let sig_list = buffer.decode_exact::<SignatureSchemeList>()?;
                sig_list
                    .supported_signature_algorithms
                    .list
                    .to_vec()
            }
            None => return Ok(None),
        };
        Ok(Some(sigs))
    }

    pub fn supported_versions(&self) -> Result<Vec<Version>, Box<dyn std::error::Error>> {
        let bytes = self
            .client_hello
            .get_extension(Self::SUPPORTED_VERSIONS_ID)?;
        let versions = match bytes {
            // the client sent the supported versions extension -> return the values
            Some(buffer) => {
                let buffer = DecoderBuffer::new(&buffer);
                let supported_groups = buffer.decode_exact::<SupportedVersionsClientHello>()?;
                supported_groups.versions.list.to_vec()
            }
            // the client didn't send the supported versions extension, so just
            // return the protocol version value from the client hello
            None => {
                let client_hello_bytes = self.client_hello.raw_message()?;
                let client_hello_buffer = DecoderBuffer::new(&client_hello_bytes);
                let client_hello = client_hello_buffer.decode_exact::<ClientHello>()?;
                vec![client_hello.protocol_version]
            }
        };
        Ok(versions)
    }
}

/// We generally discourage the use of direct extension retrieval so it isn't exposed
/// in the s2n-tls crate.
trait S2NClientHelloExtension {
    fn get_extension(&self, extension_id: u16) -> Result<Option<Vec<u8>>, s2n_tls::error::Error>;
}

impl S2NClientHelloExtension for s2n_tls::client_hello::ClientHello {
    /// Retrieve the extension_data from some particular extension
    ///
    /// The extension ID should be one of the values from this list:
    /// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
    fn get_extension(&self, extension_id: u16) -> Result<Option<Vec<u8>>, s2n_tls::error::Error> {
        // we are depending on an internal implementation detail, where ClientHello
        // is aliased to the raw s2n_tls_sys type. Below is a compile-time assertion
        // that this hasn't changed. Even if the change isn't run through
        // s2n-tls CI, customers will fail to build instead of
        // encountering a runtime error.
        static_assertions::assert_eq_size!(
            s2n_tls::client_hello::ClientHello,
            s2n_tls_sys::s2n_client_hello
        );

        let raw_ch =
            self as *const s2n_tls::client_hello::ClientHello as *mut s2n_tls_sys::s2n_client_hello;
        let extension_length = unsafe {
            s2n_client_hello_get_extension_length(raw_ch, extension_id as c_uint).into_result()
        }?;
        if extension_length == 0 {
            return Ok(None);
        }

        let mut extension_data = vec![0; extension_length];
        let written_length = unsafe {
            s2n_client_hello_get_extension_by_id(
                raw_ch,
                extension_id as c_uint,
                extension_data.as_mut_ptr(),
                extension_data.len() as u32,
            )
            .into_result()
        }?;

        debug_assert_eq!(extension_length, written_length);

        Ok(Some(extension_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    use s2n_codec::{DecoderBuffer, zerocopy::U16};
    use s2n_tls::{
        security::Policy,
        testing::{TestPair, build_config},
    };

    use crate::{
        parsing::{ClientHelloSupportedParameters, messages::ClientHello},
        test_utils::ARBITRARY_POLICY_1,
    };
    use s2n_tls::error::Error as S2NError;

    struct SecurityPolicySupportedParameters {
        cipher: Vec<Cipher>,
        groups: Vec<Group>,
        signatures: Vec<Signature>,
    }

    impl SecurityPolicySupportedParameters {
        fn new(policy_name: &'static str) -> Self {
            let sp = s2n_tls_sys_internal::security_policy_table()
                .iter()
                .find(|security_policy| {
                    let current_name = unsafe { CStr::from_ptr(security_policy.version) };
                    current_name.to_str().unwrap() == policy_name
                })
                .map(|sp| unsafe { &*sp.security_policy })
                .unwrap();

            let cipher: Vec<Cipher> = sp.ciphers().iter().map(|c| Cipher(c.iana_value)).collect();

            let groups: Vec<Group> = sp
                .curves()
                .iter()
                .map(|c| Group(U16::new(c.iana_id)))
                .chain(sp.kems().iter().map(|k| Group(U16::new(k.iana_id))))
                .collect();

            let signatures: Vec<Signature> = sp
                .signatures()
                .iter()
                .map(|s| Signature(U16::new(s.iana_value)))
                .collect();

            Self {
                cipher,
                groups,
                signatures,
            }
        }
    }

    /// Return a server connection that has handshaken with a client using `policy`.
    fn server_connection(policy: &s2n_tls::security::Policy) -> s2n_tls::connection::Connection {
        let config = build_config(policy).unwrap();
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();
        pair.server
    }

    #[test]
    fn client_hello_parsing_sanity_check() -> Result<(), S2NError> {
        let sp = server_connection(&ARBITRARY_POLICY_1);
        let client_hello = sp.client_hello()?;
        let client_hello_bytes = client_hello.raw_message()?;
        let buffer = DecoderBuffer::new(&client_hello_bytes);
        let parsed_client_hello = buffer.decode_exact::<ClientHello>().unwrap();
        assert_eq!(
            parsed_client_hello.legacy_session_id.blob,
            client_hello.session_id()?.as_slice()
        );

        Ok(())
    }

    /// iterate through s2n-tls security policy structs and send a client hello
    /// for each one. Then confirm that [`ClientHelloSupportedParameters`] detects
    /// all of the parameters in the underlying security policy.
    #[test]
    fn expected_supported_parameters() {
        let mut tested_policies = 0;

        for entry in s2n_tls_sys_internal::security_policy_table() {
            let policy_name = unsafe { CStr::from_ptr(entry.version) }.to_str().unwrap();
            let policy = Policy::from_version(policy_name).unwrap();

            let expected = SecurityPolicySupportedParameters::new(policy_name);

            // some policies are incompatible with the default test certs
            let pair = std::panic::catch_unwind(|| {
                let config = build_config(&policy).unwrap();
                let mut pair = TestPair::from_config(&config);
                pair.handshake().unwrap();
                pair
            });
            let pair = match pair {
                Ok(p) => p,
                Err(_) => continue,
            };
            let client_hello = pair.server.client_hello().unwrap();
            let parsed = ClientHelloSupportedParameters::new(client_hello);

            let offered_ciphers = parsed.supported_ciphers().unwrap();
            for cipher in &expected.cipher {
                assert!(offered_ciphers.contains(cipher));
            }

            if let Some(offered_groups) = parsed.supported_groups().unwrap() {
                for group in &expected.groups {
                    assert!(offered_groups.contains(group));
                }
            }

            if let Some(offered_sigs) = parsed.supported_signatures().unwrap() {
                for sig in &expected.signatures {
                    assert!(offered_sigs.contains(sig),);
                }
            }
            tested_policies += 1;
        }

        // This test is a bit "fuzzy" because the security policy might not support
        // our cert, etc. So just assert that we tested on a decent number of security
        // policies
        assert!(tested_policies > 100);
    }

    /// the list of supported protocol versions is not directly contained in the
    /// security policy so instead use a number of known security policies.
    #[test]
    fn expected_protocol_version() {
        let test_cases = vec![
            // only TLS 1.3 - we should correctly ignore the fake "TLS 1.2" value in
            // the ClientHello `protocol_version` field.
            ("AWS-CRT-SDK-TLSv1.3-2023", vec![Version::TLS_1_3]),
            // TLS 1.3 -> TLS 1.0
            (
                "20190802",
                vec![
                    Version::TLS_1_3,
                    Version::TLS_1_2,
                    Version::TLS_1_1,
                    Version::TLS_1_0,
                ],
            ),
            // TLS 1.2 -> TLS 1.0 - we only report the one value because the
            // supported_versions extension isn't present
            ("20190214", vec![Version::TLS_1_2]),
        ];

        for (policy, expected_result) in test_cases {
            let policy = Policy::from_version(policy).unwrap();
            let connection = server_connection(&policy);
            let client_hello = connection.client_hello().unwrap();
            let supported_parameters = ClientHelloSupportedParameters::new(client_hello);
            assert_eq!(
                supported_parameters.supported_versions().unwrap(),
                expected_result
            );
        }
    }
}
