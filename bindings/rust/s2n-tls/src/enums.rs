// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::missing_safety_doc)] // TODO add safety docs

use crate::error::Error;
use core::convert::TryFrom;
use s2n_tls_sys::*;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum CallbackResult {
    Success,
    Failure,
}

impl From<CallbackResult> for s2n_status_code::Type {
    fn from(input: CallbackResult) -> s2n_status_code::Type {
        match input {
            CallbackResult::Success => s2n_status_code::SUCCESS,
            CallbackResult::Failure => s2n_status_code::FAILURE,
        }
    }
}

impl<T, E> From<Result<T, E>> for CallbackResult {
    fn from(result: Result<T, E>) -> CallbackResult {
        match result {
            Ok(_) => CallbackResult::Success,
            Err(_) => CallbackResult::Failure,
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Mode {
    Server,
    Client,
}

impl From<Mode> for s2n_mode::Type {
    fn from(input: Mode) -> s2n_mode::Type {
        match input {
            Mode::Server => s2n_mode::SERVER,
            Mode::Client => s2n_mode::CLIENT,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Version {
    SSLV2,
    SSLV3,
    TLS10,
    TLS11,
    TLS12,
    TLS13,
}

impl TryFrom<s2n_tls_version::Type> for Version {
    type Error = Error;

    fn try_from(input: s2n_tls_version::Type) -> Result<Self, Self::Error> {
        let version = match input {
            s2n_tls_version::SSLV2 => Self::SSLV2,
            s2n_tls_version::SSLV3 => Self::SSLV3,
            s2n_tls_version::TLS10 => Self::TLS10,
            s2n_tls_version::TLS11 => Self::TLS11,
            s2n_tls_version::TLS12 => Self::TLS12,
            s2n_tls_version::TLS13 => Self::TLS13,
            _ => return Err(Error::INVALID_INPUT),
        };
        Ok(version)
    }
}

#[non_exhaustive]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Blinding {
    SelfService,
    BuiltIn,
}

impl From<Blinding> for s2n_blinding::Type {
    fn from(input: Blinding) -> s2n_blinding::Type {
        match input {
            Blinding::SelfService => s2n_blinding::SELF_SERVICE_BLINDING,
            Blinding::BuiltIn => s2n_blinding::BUILT_IN_BLINDING,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ClientAuthType {
    Required,
    Optional,
    None,
}

impl From<ClientAuthType> for s2n_cert_auth_type::Type {
    fn from(input: ClientAuthType) -> s2n_cert_auth_type::Type {
        match input {
            ClientAuthType::Required => s2n_cert_auth_type::REQUIRED,
            ClientAuthType::Optional => s2n_cert_auth_type::OPTIONAL,
            ClientAuthType::None => s2n_cert_auth_type::NONE,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum AlertBehavior {
    FailOnWarnings,
    IgnoreWarnings,
}

impl From<AlertBehavior> for s2n_alert_behavior::Type {
    fn from(input: AlertBehavior) -> s2n_alert_behavior::Type {
        match input {
            AlertBehavior::FailOnWarnings => s2n_alert_behavior::FAIL_ON_WARNINGS,
            AlertBehavior::IgnoreWarnings => s2n_alert_behavior::IGNORE_WARNINGS,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, PartialEq, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum SignatureAlgorithm {
    RSA_PKCS1,
    RSA_PSS_RSAE,
    RSA_PSS_PSS,
    ECDSA,
}

impl TryFrom<s2n_tls_signature_algorithm::Type> for SignatureAlgorithm {
    type Error = Error;

    fn try_from(input: s2n_tls_signature_algorithm::Type) -> Result<Self, Self::Error> {
        let version = match input {
            s2n_tls_signature_algorithm::RSA => Self::RSA_PKCS1,
            s2n_tls_signature_algorithm::RSA_PSS_RSAE => Self::RSA_PSS_RSAE,
            s2n_tls_signature_algorithm::RSA_PSS_PSS => Self::RSA_PSS_PSS,
            s2n_tls_signature_algorithm::ECDSA => Self::ECDSA,
            _ => return Err(Error::INVALID_INPUT),
        };
        Ok(version)
    }
}

#[non_exhaustive]
#[derive(Debug, PartialEq, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum HashAlgorithm {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

impl TryFrom<s2n_tls_hash_algorithm::Type> for HashAlgorithm {
    type Error = Error;

    fn try_from(input: s2n_tls_hash_algorithm::Type) -> Result<Self, Self::Error> {
        let version = match input {
            s2n_tls_hash_algorithm::MD5 => Self::MD5,
            s2n_tls_hash_algorithm::SHA1 => Self::SHA1,
            s2n_tls_hash_algorithm::SHA224 => Self::SHA224,
            s2n_tls_hash_algorithm::SHA256 => Self::SHA256,
            s2n_tls_hash_algorithm::SHA384 => Self::SHA384,
            s2n_tls_hash_algorithm::SHA512 => Self::SHA512,
            _ => return Err(Error::INVALID_INPUT),
        };
        Ok(version)
    }
}
