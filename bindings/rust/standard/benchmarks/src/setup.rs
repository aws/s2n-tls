// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{CipherSuite, CryptoConfig, HandshakeType, KXGroup, TlsBenchConfig};

use std::{error::Error, sync::Arc};
use tls_harness::{
    cohort::{self, S2NConfig},
    get_cert_path,
    harness::{read_to_bytes, Mode},
    PemType::*,
};

mod openssl_bench_setup {
    use super::*;
    use openssl::ssl::{
        SslContext, SslFiletype, SslMethod, SslOptions, SslSessionCacheMode, SslVerifyMode,
        SslVersion,
    };
    impl TlsBenchConfig for cohort::OpenSslConfig {
        fn make_config(
            mode: Mode,
            crypto_config: super::CryptoConfig,
            handshake_type: super::HandshakeType,
        ) -> Result<Self, Box<dyn Error>> {
            let cipher_suite = match crypto_config.cipher_suite {
                CipherSuite::TLS_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
                super::CipherSuite::TLS_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
            };

            let ec_key = match crypto_config.kx_group {
                KXGroup::Secp256R1 => "P-256",
                KXGroup::X25519 => "X25519",
            };

            let ssl_method = match mode {
                Mode::Client => SslMethod::tls_client(),
                Mode::Server => SslMethod::tls_server(),
            };

            let session_ticket_storage = cohort::openssl::SessionTicketStorage::default();

            let mut builder = SslContext::builder(ssl_method)?;
            builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
            builder.set_ciphersuites(cipher_suite)?;
            builder.set_groups_list(ec_key)?;

            match mode {
                Mode::Client => {
                    builder.set_ca_file(get_cert_path(CACert, crypto_config.sig_type))?;
                    builder.set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);

                    match handshake_type {
                        HandshakeType::MutualAuth => {
                            builder.set_certificate_chain_file(get_cert_path(
                                ClientCertChain,
                                crypto_config.sig_type,
                            ))?;
                            builder.set_private_key_file(
                                get_cert_path(ClientKey, crypto_config.sig_type),
                                SslFiletype::PEM,
                            )?;
                        }
                        HandshakeType::Resumption => {
                            builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
                            // do not attempt to define the callback outside of an
                            // expression directly passed into the function, because
                            // the compiler's type inference doesn't work for this
                            // scenario
                            // https://github.com/rust-lang/rust/issues/70263
                            builder.set_new_session_callback({
                                let sts = session_ticket_storage.clone();
                                move |_, ticket| {
                                    let _ = sts.stored_ticket.lock().unwrap().insert(ticket);
                                }
                            });
                        }
                        HandshakeType::ServerAuth => {}
                    }
                }
                Mode::Server => {
                    builder.set_certificate_chain_file(get_cert_path(
                        ServerCertChain,
                        crypto_config.sig_type,
                    ))?;
                    builder.set_private_key_file(
                        get_cert_path(ServerKey, crypto_config.sig_type),
                        SslFiletype::PEM,
                    )?;

                    if handshake_type == HandshakeType::MutualAuth {
                        builder.set_ca_file(get_cert_path(CACert, crypto_config.sig_type))?;
                        builder
                            .set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);
                    }
                    if handshake_type == HandshakeType::Resumption {
                        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
                    } else {
                        builder.set_options(SslOptions::NO_TICKET);
                        builder.set_session_cache_mode(SslSessionCacheMode::OFF);
                        // OpenSSL Bug: https://github.com/openssl/openssl/issues/8077
                        // even with the above configuration, we must explicitly specify
                        // 0 tickets
                        builder.set_num_tickets(0)?;
                    }
                }
            }
            Ok(Self {
                config: builder.build(),
                session_ticket_storage,
            })
        }
    }
}

mod rustls_bench_setup {
    use super::*;
    use rustls::{
        crypto::{
            aws_lc_rs::{self, kx_group},
            CryptoProvider,
        },
        server::WebPkiClientVerifier,
        version, ClientConfig, ServerConfig,
    };
    use tls_harness::cohort::rustls::NoOpTicketer;

    impl TlsBenchConfig for cohort::RustlsConfig {
        fn make_config(
            mode: Mode,
            crypto_config: CryptoConfig,
            handshake_type: HandshakeType,
        ) -> Result<Self, Box<dyn Error>> {
            let cipher_suite = match crypto_config.cipher_suite {
                CipherSuite::TLS_AES_128_GCM_SHA256 => {
                    aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
                }
                CipherSuite::TLS_AES_256_GCM_SHA384 => {
                    aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384
                }
            };

            let kx_group = match crypto_config.kx_group {
                KXGroup::Secp256R1 => &kx_group::SECP256R1,
                KXGroup::X25519 => &kx_group::X25519,
            };

            let crypto_provider = Arc::new(CryptoProvider {
                cipher_suites: vec![cipher_suite],
                kx_groups: vec![*kx_group],
                ..aws_lc_rs::default_provider()
            });

            match mode {
                Mode::Client => {
                    let builder = ClientConfig::builder_with_provider(crypto_provider)
                        .with_protocol_versions(&[&version::TLS13])?
                        .with_root_certificates(Self::get_root_cert_store(crypto_config.sig_type));

                    let config = match handshake_type {
                        HandshakeType::ServerAuth | HandshakeType::Resumption => {
                            builder.with_no_client_auth()
                        }
                        HandshakeType::MutualAuth => builder.with_client_auth_cert(
                            Self::get_cert_chain(ClientCertChain, crypto_config.sig_type),
                            Self::get_key(ClientKey, crypto_config.sig_type),
                        )?,
                    };

                    if handshake_type != HandshakeType::Resumption {
                        rustls::client::Resumption::disabled();
                    }

                    Ok(cohort::RustlsConfig::Client(Arc::new(config)))
                }
                Mode::Server => {
                    let builder = ServerConfig::builder_with_provider(crypto_provider)
                        .with_protocol_versions(&[&version::TLS13])?;

                    let builder = match handshake_type {
                        HandshakeType::ServerAuth | HandshakeType::Resumption => {
                            builder.with_no_client_auth()
                        }
                        HandshakeType::MutualAuth => {
                            let client_cert_verifier = WebPkiClientVerifier::builder(
                                Self::get_root_cert_store(crypto_config.sig_type).into(),
                            )
                            .build()
                            .unwrap();
                            builder.with_client_cert_verifier(client_cert_verifier)
                        }
                    };

                    let mut config = builder.with_single_cert(
                        Self::get_cert_chain(ServerCertChain, crypto_config.sig_type),
                        Self::get_key(ServerKey, crypto_config.sig_type),
                    )?;

                    if handshake_type != HandshakeType::Resumption {
                        config.session_storage =
                            Arc::new(rustls::server::NoServerSessionStorage {});
                        config.ticketer = Arc::new(NoOpTicketer {});
                    }

                    Ok(cohort::RustlsConfig::Server(Arc::new(config)))
                }
            }
        }
    }
}

mod s2n_tls_bench_setup {
    use std::time::SystemTime;

    use super::*;

    use s2n_tls::{enums::ClientAuthType, security::Policy};
    impl TlsBenchConfig for cohort::S2NConfig {
        fn make_config(
            mode: Mode,
            crypto_config: CryptoConfig,
            handshake_type: HandshakeType,
        ) -> Result<Self, Box<dyn Error>> {
            // these security policies negotiate the given cipher suite and key
            // exchange group as their top choice
            let security_policy = match (crypto_config.cipher_suite, crypto_config.kx_group) {
                (CipherSuite::TLS_AES_128_GCM_SHA256, KXGroup::Secp256R1) => "20230317",
                (CipherSuite::TLS_AES_256_GCM_SHA384, KXGroup::Secp256R1) => "20190802",
                (CipherSuite::TLS_AES_128_GCM_SHA256, KXGroup::X25519) => "20240417",
                (CipherSuite::TLS_AES_256_GCM_SHA384, KXGroup::X25519) => "20190801",
            };

            let mut builder = s2n_tls::config::Builder::new();
            builder
                .set_security_policy(&Policy::from_version(security_policy)?)?
                .with_system_certs(false)?
                .set_client_auth_type(match handshake_type {
                    HandshakeType::MutualAuth => ClientAuthType::Required,
                    _ => ClientAuthType::None, // ServerAuth or resumption handshake
                })?;

            if handshake_type == HandshakeType::Resumption {
                builder.enable_session_tickets(true)?;
            }

            let session_ticket_storage = cohort::s2n_tls::SessionTicketStorage::default();

            match mode {
                Mode::Client => {
                    builder
                        .trust_pem(read_to_bytes(CACert, crypto_config.sig_type).as_slice())?
                        .set_verify_host_callback(cohort::s2n_tls::LOCALHOST_VERIFY_CALLBACK)?;

                    match handshake_type {
                        HandshakeType::MutualAuth => {
                            builder.load_pem(
                                read_to_bytes(ClientCertChain, crypto_config.sig_type).as_slice(),
                                read_to_bytes(ClientKey, crypto_config.sig_type).as_slice(),
                            )?;
                        }
                        HandshakeType::Resumption => {
                            builder.set_session_ticket_callback(session_ticket_storage.clone())?;
                        }
                        // no special configuration
                        HandshakeType::ServerAuth => {}
                    }
                }
                Mode::Server => {
                    builder.load_pem(
                        read_to_bytes(ServerCertChain, crypto_config.sig_type).as_slice(),
                        read_to_bytes(ServerKey, crypto_config.sig_type).as_slice(),
                    )?;

                    match handshake_type {
                        HandshakeType::MutualAuth => {
                            builder
                                .trust_pem(
                                    read_to_bytes(CACert, crypto_config.sig_type).as_slice(),
                                )?
                                .set_verify_host_callback(
                                    cohort::s2n_tls::LOCALHOST_VERIFY_CALLBACK,
                                )?;
                        }
                        HandshakeType::Resumption => {
                            builder.add_session_ticket_key(
                                cohort::s2n_tls::KEY_NAME.as_bytes(),
                                cohort::s2n_tls::KEY_VALUE.as_slice(),
                                // use a time that we are sure is in the past to
                                // make the key immediately available
                                SystemTime::UNIX_EPOCH,
                            )?;
                        }
                        // no special configuration for normal handshake
                        HandshakeType::ServerAuth => {}
                    };
                }
            }

            Ok(S2NConfig {
                config: builder.build()?,
                ticket_storage: session_ticket_storage,
            })
        }
    }
}
