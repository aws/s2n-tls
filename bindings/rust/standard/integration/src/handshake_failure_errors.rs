// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use brass_aphid_wire_decryption::decryption::key_manager::KeyManager;
use brass_aphid_wire_messages::{
    iana::{self},
    protocol::{
        content_value::{ContentValue, HandshakeMessageValue},
        AlertDescription, AlertLevel,
    },
};
use openssl::ssl::{SslContextBuilder, SslVersion};
use s2n_tls::{error::ErrorType, security::Policy, testing::TestPair};
use tls_harness::{
    cohort::{s2n_tls::HostNameHandler, OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    TlsConnPair,
};

use crate::{
    capability_check::{required_capability, required_capability_with_inner_result, Capability},
    utilities::certs::{self, CertMaterials},
};

#[test]
fn no_protocols_in_common() {
    required_capability(&[Capability::Tls13], || {
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let tls13_only_policy = Policy::from_version("20250414").unwrap();
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs
                .server
                .set_security_policy(&tls13_only_policy)
                .unwrap();
            configs
                .client
                .set_max_proto_version(Some(SslVersion::TLS1_2))
                .unwrap();

            configs.connection_pair()
        };

        let error = pair.handshake().unwrap_err();
        let s2n_error: Box<s2n_tls::error::Error> = error.downcast().unwrap();
        assert_eq!(s2n_error.kind(), ErrorType::ProtocolError);
        assert_eq!(s2n_error.name(), "S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED");
        assert_eq!(
            s2n_error.message(),
            "TLS protocol version is not supported by configuration"
        );
    });
}

#[test]
fn no_ciphers_in_common() {
    required_capability(&[Capability::Tls13], || {
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let tls13_only_policy = Policy::from_version("20250414").unwrap();
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs
                .server
                .set_security_policy(&tls13_only_policy)
                .unwrap();
            configs
                .client
                .set_ciphersuites("TLS_SHA256_SHA256")
                .unwrap();

            configs.connection_pair()
        };

        let error = pair.handshake().unwrap_err();
        let s2n_error: Box<s2n_tls::error::Error> = error.downcast().unwrap();
        assert_eq!(s2n_error.kind(), ErrorType::ProtocolError);
        assert_eq!(s2n_error.name(), "S2N_ERR_CIPHER_NOT_SUPPORTED");
        assert_eq!(s2n_error.message(), "Cipher is not supported");
    })
}

#[test]
fn no_groups_in_common() {
    required_capability(&[Capability::Tls13], || {
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let tls13_only_policy = Policy::from_version("20250414").unwrap();
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs
                .server
                .set_security_policy(&tls13_only_policy)
                .unwrap();
            configs.client.set_groups_list("x448").unwrap();

            configs.connection_pair()
        };

        let error = pair.handshake().unwrap_err();
        let s2n_error: Box<s2n_tls::error::Error> = error.downcast().unwrap();
        assert_eq!(s2n_error.kind(), ErrorType::InternalError);
        assert_eq!(s2n_error.name(), "S2N_ERR_INVALID_SUPPORTED_GROUP_STATE");
        assert_eq!(s2n_error.message(), "SupportedGroup preference decision entered invalid state and selected both KEM and EC Curve");
    })
}

/// When there are no signature schemes in common, s2n-tls will make a "best effort"
/// to proceed with the handshake anyways. This means that s2n-tls won't actually
/// fail the connection, and instead it will show up as an alert from the peer.
#[test]
fn no_signatures_in_common() {
    required_capability(&[Capability::Tls13], || {
        let key_manager = KeyManager::new();

        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            // "20250211" doesn't allow any SHA256 signatures
            let sha384_only_policy = Policy::from_version("20250211").unwrap();
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs
                .server
                .set_security_policy(&sha384_only_policy)
                .unwrap();
            key_manager.enable_s2n_logging(&mut configs.server);
            configs
                .client
                .set_sigalgs_list("rsa_pss_pss_sha256")
                .unwrap();

            configs.connection_pair()
        };
        pair.io.enable_decryption(key_manager);

        let error = pair.handshake().unwrap_err();
        let ossl_error: Box<openssl::ssl::Error> = error.downcast().unwrap();
        // the client/openssl fails when checking the signature, because s2n-tls sent
        // a signature that it did not advertise support for
        // Error {
        // code: ErrorCode(1),
        // cause: Some(Ssl(ErrorStack([
        //      Error {
        //          code: 167772530,
        //          library: "SSL routines",
        //          function: "tls12_check_peer_sigalg",
        //          reason: "wrong signature type",
        //          file: "ssl/t1_lib.c",
        //          line: 2797 }
        // ]))) }
        assert!(ossl_error.to_string().contains("tls12_check_peer_sigalg"));
        assert!(ossl_error.to_string().contains("wrong signature type"));

        let transcript = pair.io.decrypter.borrow().as_ref().unwrap().transcript();
        let content = transcript.content_transcript.lock().unwrap().clone();

        // confirm that s2n-tls sent an unexpected signature.
        {
            let certificate_verify = content
                .iter()
                .filter_map(|(_sender, content_value)| match content_value {
                    ContentValue::Handshake(HandshakeMessageValue::CertVerifyTls13(
                        cert_verify,
                    )) => Some(cert_verify),
                    _ => None,
                })
                .next()
                .unwrap();
            // s2n-tls send a certificate verify with rsa_pss_rsae_sha384, which is not
            // one of the client's supported signature algorithms
            assert_eq!(
                certificate_verify.algorithm,
                iana::constants::rsa_pss_rsae_sha384
            );
        }

        // confirm that the client sent an alert indicating its displeasure
        {
            let alert = content
                .iter()
                .filter(|(sender, _content)| {
                    *sender == brass_aphid_wire_decryption::decryption::Mode::Client
                })
                .filter_map(|(_sender, content_value)| match content_value {
                    ContentValue::Alert(alert) => Some(alert),
                    _ => None,
                })
                .next()
                .unwrap();
            assert_eq!(alert.level, AlertLevel::Fatal);
            assert_eq!(alert.description, AlertDescription::HandshakeFailure)
        }
    })
}

#[test]
fn host_name_verification() {
    let cert = &certs::BEAVER;
    const HOST_NAME: &str = "www.beaver.com";

    let server = {
        let mut server = s2n_tls::config::Builder::new();
        server
            .load_pem(&cert.server_chain(), &cert.server_key())
            .unwrap();
        server.build().unwrap()
    };

    let client = {
        let mut client = s2n_tls::config::Builder::new();
        client.trust_pem(&cert.ca()).unwrap();
        client.build().unwrap()
    };

    // sanity check: handshake succeeds when the right hostname is set.
    {
        let mut pair = TestPair::from_configs(&client, &server);
        pair.client.set_server_name(HOST_NAME).unwrap();
        pair.handshake().unwrap();
    }

    // failure: the server_name is not set, so the default hostname verify cb will fail
    {
        let mut pair = TestPair::from_configs(&client, &server);
        let err = pair.handshake().unwrap_err();
        // Error {
        //     code: 335544366,
        //     name: "S2N_ERR_CERT_UNTRUSTED",
        //     message: "Certificate is untrusted",
        //     kind: ProtocolError,
        //     source: Library,
        //     debug: "Error encountered in lib/utils/s2n_io.c:26", <- badge of shame
        //     errno: "Success"
        // }
        assert_eq!(err.kind(), ErrorType::ProtocolError);
        assert_eq!(err.name(), "S2N_ERR_CERT_UNTRUSTED");
    }
}

/// When a client cert chain is signed with signatures that aren't allowed by the
/// `certificate_signature_preferences` field in the security policy we return an
/// S2N_ERR_CERT_UNTRUSTED error
#[test]
fn mtls_cert_signature_not_allowed() {
    /// Certificate Signatures must have a SHA384 digest
    /// Transcript Signatures must have a SHA384 digest
    /// Certificate keys must be RSA3072 or secp384r1
    const POLICY: &str = "20251013";

    required_capability_with_inner_result(&[Capability::Tls13], || {
        let server_cert = CertMaterials::from_permutation("rsae_pkcs_3072_sha384");
        // The client cert has a valid key (RSA3072) but an invalid signature
        // (SHA256 digest)
        let client_cert = CertMaterials::from_permutation("rsae_pkcs_3072_sha256");

        let mut pair: TlsConnPair<S2NConnection, S2NConnection> = {
            let sha384_only_policy = Policy::from_version(POLICY)?;
            let mut server = s2n_tls::config::Builder::new();

            server
                .set_security_policy(&sha384_only_policy)?
                .set_verify_host_callback(HostNameHandler::new("localhost"))?
                .load_pem(&server_cert.server_chain(), &server_cert.server_key())?
                .set_client_auth_type(s2n_tls::enums::ClientAuthType::Required)?
                .trust_pem(&client_cert.ca())?;
            let server = server.build().unwrap();

            let mut client = s2n_tls::config::Builder::new();
            client
                .set_verify_host_callback(HostNameHandler::new("localhost"))?
                .load_pem(&client_cert.server_chain(), &client_cert.server_key())?
                .trust_pem(&server_cert.ca())?;
            let client = client.build().unwrap();

            TlsConnPair::from_configs(&client.into(), &server.into())
        };

        let error = pair.handshake().unwrap_err();
        let s2n_error: Box<s2n_tls::error::Error> = error.downcast()?;
        assert_eq!(s2n_error.kind(), ErrorType::ProtocolError);
        assert_eq!(s2n_error.name(), "S2N_ERR_CERT_UNTRUSTED");
        Ok(())
    });
}

/// When a client cert chain uses keys that aren't allowed by the `certificate_key_preferences`
/// field in the security policy, we return an S2N_ERR_CERT_UNTRUSTED error
#[test]
fn mtls_cert_key_not_allowed() {
    /// Certificate Signatures must have a SHA384 digest
    /// Transcript Signatures must have a SHA384 digest
    /// Certificate keys must be RSA3072 or secp384r1
    const POLICY: &str = "20251013";

    required_capability_with_inner_result(&[Capability::Tls13], || {
        let server_cert = CertMaterials::from_permutation("ec_ecdsa_p384_sha384");
        // the cert has a valid signature (ECDSA+SHA384) but an invalid key (p256).
        let client_cert = CertMaterials::from_permutation("ec_ecdsa_p256_sha384");

        let mut pair: TlsConnPair<S2NConnection, S2NConnection> = {
            let policy = Policy::from_version(POLICY)?;

            let mut server = s2n_tls::config::Builder::new();
            server
                .set_verify_host_callback(HostNameHandler::new("localhost"))?
                .load_pem(&server_cert.server_chain(), &server_cert.server_key())?
                .set_security_policy(&policy)?
                .set_client_auth_type(s2n_tls::enums::ClientAuthType::Required)?
                .trust_pem(&client_cert.ca())?;
            let server = server.build()?;

            let mut client = s2n_tls::config::Builder::new();

            client
                .set_verify_host_callback(HostNameHandler::new("localhost"))?
                .load_pem(&client_cert.server_chain(), &client_cert.server_key())?
                .trust_pem(&server_cert.ca())?;
            let client = client.build()?;
            TlsConnPair::from_configs(&client.into(), &server.into())
        };

        let error = pair.handshake().unwrap_err();
        let s2n_error: Box<s2n_tls::error::Error> = error.downcast()?;
        println!("{s2n_error:?}");
        assert_eq!(s2n_error.kind(), ErrorType::ProtocolError);
        assert_eq!(s2n_error.name(), "S2N_ERR_CERT_UNTRUSTED");
        Ok(())
    });
}

/// When a server is doing mTLS, it sends a CertificateRequest to the client
/// which includes the server's supported signature algorithms. For TLS 1.3, this
/// will restrict the _key type_ of ECDSA certs, because TLS 1.3 added key type
/// as part of the signature specification.
///
/// So the handshake will either fail
/// - at the client side, because it recognizes that it doesn't have an ECDSA cert
///   capable of generating the signature that the server requires.
/// - at the server side, because the client makes a "best effort" to continue and
///   then the server is responsible for rejecting it.
///
/// This test documents the various failure modes of different TLS implementations.
#[test]
fn mtls_tls13_transcript_signature_not_negotiable() {
    /// allows a wide range of certificate signatures/keys, but transcript signatures
    /// must use a SHA384 digest (ecdsa_sha384).
    const POLICY: &str = "20250211";

    required_capability_with_inner_result(&[Capability::Tls13], || {
        let server_cert = CertMaterials::from_permutation("ec_ecdsa_p384_sha384");
        // The client cert will produce an invalid transcript signature (ecdsa_secp256r1_sha256)
        // which is not allowed by the server's security policy.
        let client_cert = CertMaterials::from_permutation("ec_ecdsa_p256_sha384");

        // OpenSSL client
        {
            let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
                let policy = Policy::from_version(POLICY)?;
                let mut configs =
                    TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();

                configs
                    .server
                    .set_security_policy(&policy)?
                    .set_verify_host_callback(HostNameHandler::new("localhost"))?
                    .set_client_auth_type(s2n_tls::enums::ClientAuthType::Required)?
                    .trust_pem(&client_cert.ca())?;

                configs
                    .client
                    .set_certificate_chain_file(&client_cert.server_chain_path)?;
                configs.client.set_private_key_file(
                    &client_cert.server_key_path,
                    openssl::ssl::SslFiletype::PEM,
                )?;

                configs.connection_pair()
            };

            // OpenSSL will not send the client certificate if it doesn't satisfy
            // the server Signature Algorithm requirements.
            let error = pair.handshake().unwrap_err();
            let s2n_error: Box<s2n_tls::error::Error> = error.downcast()?;
            assert_eq!(s2n_error.kind(), ErrorType::ProtocolError);
            assert_eq!(s2n_error.name(), "S2N_ERR_MISSING_CLIENT_CERT");
        }

        // s2n-tls client
        {
            let mut pair: TlsConnPair<S2NConnection, S2NConnection> = {
                let policy = Policy::from_version(POLICY)?;
                let mut server = s2n_tls::config::Builder::new();

                server
                    .set_security_policy(&policy)?
                    .set_verify_host_callback(HostNameHandler::new("localhost"))?
                    .load_pem(&server_cert.server_chain(), &server_cert.server_key())?
                    .set_client_auth_type(s2n_tls::enums::ClientAuthType::Required)?
                    .trust_pem(&client_cert.ca())?;
                let server = server.build().unwrap();

                let mut client = s2n_tls::config::Builder::new();
                client
                    .set_verify_host_callback(HostNameHandler::new("localhost"))?
                    .load_pem(&client_cert.server_chain(), &client_cert.server_key())?
                    .trust_pem(&server_cert.ca())?;
                let client = client.build().unwrap();

                TlsConnPair::from_configs(&client.into(), &server.into())
            };

            // The s2n-tls client will "best-effort" send the transcript signature,
            // which is then rejected by the server because it isn't allowed by
            // the security policy
            let error = pair.handshake().unwrap_err();
            let s2n_error: Box<s2n_tls::error::Error> = error.downcast()?;
            assert_eq!(s2n_error.kind(), ErrorType::ProtocolError);
            assert_eq!(s2n_error.name(), "S2N_ERR_INVALID_SIGNATURE_SCHEME");
        }

        Ok(())
    });
}
