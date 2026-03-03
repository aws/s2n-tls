// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module contains the static lists of all possible values emitted by the
//! s2n-tls "getter" APIs. These static lists are important because they allow us
//! to maintain an array of atomic counters instead of having to resort to a hashmap

// allowing unused lints while crate is under development, many of these structs
// won't be used until the subscriber is actually implemented
#![allow(unused)]

use std::{
    collections::HashMap,
    ffi::c_char,
    fmt::Display,
    sync::{LazyLock, Mutex},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsParam {
    /// E.g. TLS 1.2
    Version,
    /// E.g. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    Cipher,
    /// E.g. SecP256r1MLKEM768
    Group,
    /// E.g. ecdsa_secp384r1_sha384
    SignatureScheme,
}

pub(crate) const GROUP_COUNT: usize = GROUPS_AVAILABLE_IN_S2N.len();
pub(crate) const CIPHER_COUNT: usize = CIPHERS_AVAILABLE_IN_S2N.len();
pub(crate) const SIGNATURE_COUNT: usize = SIGNATURE_SCHEMES_AVAILABLE_IN_S2N.len();
pub(crate) const PROTOCOL_COUNT: usize = VERSIONS_AVAILABLE_IN_S2N.len();

use s2n_codec::{zerocopy::U16, DecoderValue};
#[cfg(test)]
use s2n_tls_sys_internal::{
    s2n_cipher_suite, s2n_ecc_named_curve, s2n_kem_group, s2n_signature_scheme,
};
use zerocopy::{BigEndian, ByteOrder, FromBytes, Immutable, Order, Unaligned};

impl TlsParam {
    pub fn index_to_description(&self, index: usize) -> Option<&'static str> {
        match self {
            TlsParam::Version => VERSIONS_AVAILABLE_IN_S2N.get(index).copied(),
            TlsParam::Cipher => CIPHERS_AVAILABLE_IN_S2N
                .get(index)
                .map(|name| name.iana_description),
            TlsParam::Group => GROUPS_AVAILABLE_IN_S2N
                .get(index)
                .map(|name| name.iana_description),
            TlsParam::SignatureScheme => SIGNATURE_SCHEMES_AVAILABLE_IN_S2N
                .get(index)
                .map(|name| name.description),
        }
    }

    pub fn description_to_index(&self, name: &str) -> Option<usize> {
        match self {
            TlsParam::Version => VERSIONS_AVAILABLE_IN_S2N
                .iter()
                .position(|version| *version == name),
            TlsParam::Cipher => CIPHERS_AVAILABLE_IN_S2N
                .iter()
                .position(|cipher| cipher.iana_description == name),
            TlsParam::Group => GROUPS_AVAILABLE_IN_S2N
                .iter()
                .position(|group| group.iana_description == name),
            TlsParam::SignatureScheme => SIGNATURE_SCHEMES_AVAILABLE_IN_S2N
                .iter()
                .position(|sig| sig.description == name),
        }
    }
}

impl Display for TlsParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsParam::Version => write!(f, "version"),
            TlsParam::Cipher => write!(f, "cipher"),
            TlsParam::Group => write!(f, "group"),
            TlsParam::SignatureScheme => write!(f, "signature_scheme"),
        }
    }
}

/// get the counter index from the openssl name. We prefer to work with IANA id's
/// but s2n-tls returns the OpenSSL cipher name.
pub fn cipher_ossl_name_to_index(name: &str) -> Option<usize> {
    CIPHERS_AVAILABLE_IN_S2N
        .iter()
        .position(|current_cipher| *current_cipher.openssl_name == *name)
}

pub trait ToStaticString {
    fn to_static_string(&self) -> &'static str;
}

impl ToStaticString for s2n_tls::enums::Version {
    fn to_static_string(&self) -> &'static str {
        match self {
            s2n_tls::enums::Version::SSLV3 => "SSLv3",
            s2n_tls::enums::Version::TLS10 => "TLSv1_0",
            s2n_tls::enums::Version::TLS11 => "TLSv1_1",
            s2n_tls::enums::Version::TLS12 => "TLSv1_2",
            s2n_tls::enums::Version::TLS13 => "TLSv1_3",
            _ => "unknown",
        }
    }
}

/// This list should match the negotiable TLS versions in s2n-tls, and determines
/// how many "counter" slots the negotiated version metrics have.
pub const VERSIONS_AVAILABLE_IN_S2N: &[&str] =
    &["SSLv3", "TLSv1_0", "TLSv1_1", "TLSv1_2", "TLSv1_3"];

/// Convert a pointer to null terminated bytes into a static string
///
/// Safety: the memory pointed to by value is static
/// Safety: the bytes are null terminated
#[cfg(test)]
unsafe fn static_memory_to_str(value: *const c_char) -> &'static str {
    use std::ffi::CStr;
    CStr::from_ptr(value).to_str().unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Version(pub(crate) s2n_codec::zerocopy::U16);

impl Version {
    const SSL_V3: Version = Version(U16::new(0x0300));
    const TLS_1_0: Version = Version(U16::new(0x0301));
    const TLS_1_1: Version = Version(U16::new(0x0302));
    const TLS_1_2: Version = Version(U16::new(0x0303));
    const TLS_1_3: Version = Version(U16::new(0x0304));

    pub fn known_description(&self) -> Option<&'static str> {
        match *self {
            Self::SSL_V3 => Some("SSLv3"),
            Self::TLS_1_0 => Some("TLSv1.0"),
            Self::TLS_1_1 => Some("TLSv1.1"),
            Self::TLS_1_2 => Some("TLSv1.2"),
            Self::TLS_1_3 => Some("TLSv1.3"),
            _ => None,
        }
    }
}

impl<'a> DecoderValue<'a> for Version {
    fn decode(bytes: s2n_codec::DecoderBuffer<'a>) -> s2n_codec::DecoderBufferResult<'a, Self> {
        let (value, bytes) = bytes.decode()?;
        Ok((Self(value), bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Cipher(pub(crate) [u8; 2]);

impl Cipher {
    pub(crate) const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: Self = Cipher([0, 255]);

    /// e.g. "TLS_AES_256_GCM_SHA384"
    ///
    /// `None` if the group is not supported by s2n-tls
    pub fn known_description(&self) -> Option<&'static str> {
        CIPHERS_AVAILABLE_IN_S2N
            .iter()
            .find(|info| info.cipher == *self)
            .map(|info| info.iana_description)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Signature(pub(crate) s2n_codec::zerocopy::U16);

impl Signature {
    pub fn known_description(&self) -> Option<&'static str> {
        SIGNATURE_SCHEMES_AVAILABLE_IN_S2N
            .iter()
            .find(|info| info.signature == *self)
            .map(|info| info.description)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Group(pub(crate) s2n_codec::zerocopy::U16);

impl Group {
    /// e.g. "secp256r1"
    ///
    /// "unknown" if the group is not supported by s2n-tls
    pub fn known_description(&self) -> Option<&'static str> {
        GROUPS_AVAILABLE_IN_S2N
            .iter()
            .find(|info| info.group == *self)
            .map(|info| info.iana_description)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CipherInformation {
    cipher: Cipher,
    iana_description: &'static str,
    openssl_name: &'static str,
}

impl CipherInformation {
    const fn new(
        iana_description: &'static str,
        iana_value: [u8; 2],
        openssl_name: &'static str,
    ) -> Self {
        Self {
            openssl_name,
            iana_description,
            cipher: Cipher(iana_value),
        }
    }

    fn unknown(iana_value: [u8; 2]) -> Self {
        Self {
            iana_description: "unknown",
            cipher: Cipher(iana_value),
            openssl_name: "unknown",
        }
    }

    #[cfg(test)]
    fn from_s2n_cipher_suite(s2n_cipher: &s2n_cipher_suite) -> Self {
        unsafe {
            // SAFETY: the name and iana_name fields are both static, null-terminated
            // strings
            let openssl_name = static_memory_to_str(s2n_cipher.name);
            let iana_description = static_memory_to_str(s2n_cipher.iana_name);
            let iana_value = s2n_cipher.iana_value;
            Self::new(iana_description, iana_value, openssl_name)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct GroupInformation {
    iana_description: &'static str,
    group: Group,
}

impl GroupInformation {
    const fn new(iana_description: &'static str, iana_value: u16) -> Self {
        Self {
            iana_description,
            group: Group(U16::new(iana_value)),
        }
    }

    fn unknown(iana_value: u16) -> Self {
        Self {
            iana_description: "unknown",
            group: Group(U16::new(iana_value)),
        }
    }

    fn from_iana_value(iana_value: u16) -> Self {
        GROUPS_AVAILABLE_IN_S2N
            .iter()
            .find(|info| info.group.0.get() == iana_value)
            .cloned()
            .unwrap_or(Self::unknown(iana_value))
    }

    #[cfg(test)]
    fn from_s2n_kem_group(kem_group: &s2n_kem_group) -> Self {
        unsafe {
            // SAFETY: the name field is a static, null-terminated string
            let name = static_memory_to_str(kem_group.name);
            let iana_id = kem_group.iana_id;
            Self::new(name, iana_id)
        }
    }

    #[cfg(test)]
    fn from_s2n_ecc_curve(curve: &s2n_ecc_named_curve) -> Self {
        unsafe {
            // SAFETY: the name field is a static, null-terminated string
            let name = static_memory_to_str(curve.name);
            let iana_id = curve.iana_id;
            Self::new(name, iana_id)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SignatureSchemeInformation {
    /// This is the IANA description only where that is unambiguously correct.
    ///
    /// Examples of non-iana signatures include legacy hashes (e.g. `legacy_ecdsa_sha224`)
    /// and ECDSA signatures (e.g. `ecdsa_sha256`).
    description: &'static str,
    signature: Signature,
}

impl SignatureSchemeInformation {
    const fn new(iana_description: &'static str, iana_value: u16) -> Self {
        Self {
            description: iana_description,
            signature: Signature(U16::new(iana_value)),
        }
    }

    pub fn description(&self) -> &'static str {
        self.description
    }

    #[cfg(test)]
    fn from_s2n_signature_scheme(scheme: &s2n_signature_scheme) -> Self {
        unsafe {
            // SAFETY: the name field is a static, null-terminated string
            let name = static_memory_to_str(scheme.name);
            let iana_value = scheme.iana_value;
            Self::new(name, iana_value)
        }
    }
}

/// We are required to track OpenSSL naming because that is what the s2n-tls 
/// connection API's return.
#[rustfmt::skip]
pub(crate) const CIPHERS_AVAILABLE_IN_S2N: &[CipherInformation] = &[
    CipherInformation::new("TLS_AES_128_GCM_SHA256", [19, 1], "TLS_AES_128_GCM_SHA256" ),
    CipherInformation::new("TLS_AES_256_GCM_SHA384", [19, 2], "TLS_AES_256_GCM_SHA384" ),
    CipherInformation::new("TLS_CHACHA20_POLY1305_SHA256", [19, 3], "TLS_CHACHA20_POLY1305_SHA256" ),
    CipherInformation::new("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", [0, 22], "DHE-RSA-DES-CBC3-SHA" ),
    CipherInformation::new("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", [0, 51], "DHE-RSA-AES128-SHA" ),
    CipherInformation::new("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", [0, 103], "DHE-RSA-AES128-SHA256" ),
    CipherInformation::new("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", [0, 158], "DHE-RSA-AES128-GCM-SHA256" ),
    CipherInformation::new("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", [0, 57], "DHE-RSA-AES256-SHA" ),
    CipherInformation::new("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", [0, 107], "DHE-RSA-AES256-SHA256" ),
    CipherInformation::new("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", [0, 159], "DHE-RSA-AES256-GCM-SHA384" ),
    CipherInformation::new("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", [204, 170], "DHE-RSA-CHACHA20-POLY1305" ),
    CipherInformation::new("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", [192, 9], "ECDHE-ECDSA-AES128-SHA" ),
    CipherInformation::new("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", [192, 35], "ECDHE-ECDSA-AES128-SHA256" ),
    CipherInformation::new("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", [192, 43], "ECDHE-ECDSA-AES128-GCM-SHA256" ),
    CipherInformation::new("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", [192, 10], "ECDHE-ECDSA-AES256-SHA" ),
    CipherInformation::new("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", [192, 36], "ECDHE-ECDSA-AES256-SHA384" ),
    CipherInformation::new("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", [192, 44], "ECDHE-ECDSA-AES256-GCM-SHA384" ),
    CipherInformation::new("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", [204, 169], "ECDHE-ECDSA-CHACHA20-POLY1305" ),
    CipherInformation::new("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", [192, 18], "ECDHE-RSA-DES-CBC3-SHA" ),
    CipherInformation::new("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", [192, 19], "ECDHE-RSA-AES128-SHA" ),
    CipherInformation::new("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", [192, 39], "ECDHE-RSA-AES128-SHA256" ),
    CipherInformation::new("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", [192, 47], "ECDHE-RSA-AES128-GCM-SHA256" ),
    CipherInformation::new("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", [192, 20], "ECDHE-RSA-AES256-SHA" ),
    CipherInformation::new("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", [192, 40], "ECDHE-RSA-AES256-SHA384" ),
    CipherInformation::new("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", [192, 48], "ECDHE-RSA-AES256-GCM-SHA384" ),
    CipherInformation::new("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", [204, 168], "ECDHE-RSA-CHACHA20-POLY1305" ),
    CipherInformation::new("TLS_ECDHE_RSA_WITH_RC4_128_SHA", [192, 17], "ECDHE-RSA-RC4-SHA" ),
    CipherInformation::new("TLS_NULL_WITH_NULL_NULL", [0, 0], "TLS_NULL_WITH_NULL_NULL" ),
    CipherInformation::new("TLS_RSA_WITH_3DES_EDE_CBC_SHA", [0, 10], "DES-CBC3-SHA" ),
    CipherInformation::new("TLS_RSA_WITH_AES_128_CBC_SHA", [0, 47], "AES128-SHA" ),
    CipherInformation::new("TLS_RSA_WITH_AES_128_CBC_SHA256", [0, 60], "AES128-SHA256" ),
    CipherInformation::new("TLS_RSA_WITH_AES_128_GCM_SHA256", [0, 156], "AES128-GCM-SHA256" ),
    CipherInformation::new("TLS_RSA_WITH_AES_256_CBC_SHA", [0, 53], "AES256-SHA" ),
    CipherInformation::new("TLS_RSA_WITH_AES_256_CBC_SHA256", [0, 61], "AES256-SHA256" ),
    CipherInformation::new("TLS_RSA_WITH_AES_256_GCM_SHA384", [0, 157], "AES256-GCM-SHA384" ),
    CipherInformation::new("TLS_RSA_WITH_RC4_128_MD5", [0, 4], "RC4-MD5" ),
    CipherInformation::new("TLS_RSA_WITH_RC4_128_SHA", [0, 5], "RC4-SHA"),
];

pub(crate) const GROUPS_AVAILABLE_IN_S2N: &[GroupInformation] = &[
    GroupInformation::new("MLKEM1024", 514),
    GroupInformation::new("SecP256r1MLKEM768", 4587),
    GroupInformation::new("SecP384r1MLKEM1024", 4589),
    GroupInformation::new("X25519MLKEM768", 4588),
    GroupInformation::new("secp256r1", 23),
    GroupInformation::new("secp384r1", 24),
    GroupInformation::new("secp521r1", 25),
    GroupInformation::new("x25519", 29),
];

pub(crate) const SIGNATURE_SCHEMES_AVAILABLE_IN_S2N: &[SignatureSchemeInformation] = &[
    SignatureSchemeInformation::new("ecdsa_sha1", 515),
    SignatureSchemeInformation::new("ecdsa_sha256", 1027),
    SignatureSchemeInformation::new("ecdsa_sha384", 1283),
    SignatureSchemeInformation::new("ecdsa_sha512", 1539),
    SignatureSchemeInformation::new("legacy_ecdsa_sha224", 771),
    SignatureSchemeInformation::new("legacy_rsa_md5_sha1", 65535),
    SignatureSchemeInformation::new("legacy_rsa_sha224", 769),
    SignatureSchemeInformation::new("mldsa44", 2308),
    SignatureSchemeInformation::new("mldsa65", 2309),
    SignatureSchemeInformation::new("mldsa87", 2310),
    SignatureSchemeInformation::new("rsa_pkcs1_sha1", 513),
    SignatureSchemeInformation::new("rsa_pkcs1_sha256", 1025),
    SignatureSchemeInformation::new("rsa_pkcs1_sha384", 1281),
    SignatureSchemeInformation::new("rsa_pkcs1_sha512", 1537),
    SignatureSchemeInformation::new("rsa_pss_pss_sha256", 2057),
    SignatureSchemeInformation::new("rsa_pss_pss_sha384", 2058),
    SignatureSchemeInformation::new("rsa_pss_pss_sha512", 2059),
    SignatureSchemeInformation::new("rsa_pss_rsae_sha256", 2052),
    SignatureSchemeInformation::new("rsa_pss_rsae_sha384", 2053),
    SignatureSchemeInformation::new("rsa_pss_rsae_sha512", 2054),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashSet,
        ffi::{c_char, c_int, c_void, CStr},
    };

    /// return all of the ciphers defined in any s2n-tls security policy
    fn all_available_ciphers() -> Vec<CipherInformation> {
        let ciphers: HashSet<CipherInformation> = s2n_tls_sys_internal::security_policy_table()
            .iter()
            .flat_map(|sp| {
                let sp = unsafe { &*sp.security_policy };
                let names: Vec<CipherInformation> = sp
                    .ciphers()
                    .iter()
                    .cloned()
                    .map(CipherInformation::from_s2n_cipher_suite)
                    .collect();
                names
            })
            .collect();
        let mut ciphers: Vec<CipherInformation> = ciphers.into_iter().collect();
        ciphers.sort_by_key(|cipher| cipher.iana_description);
        ciphers
    }

    /// return all of the groups defined in any s2n-tls security policy
    fn all_available_groups() -> Vec<GroupInformation> {
        let groups: HashSet<GroupInformation> = s2n_tls_sys_internal::security_policy_table()
            .iter()
            .flat_map(|sp| {
                let sp = unsafe { &*sp.security_policy };
                let curves = sp
                    .curves()
                    .iter()
                    .map(|curve| GroupInformation::from_s2n_ecc_curve(curve));
                let kem_groups = sp
                    .kems()
                    .iter()
                    .map(|kem| GroupInformation::from_s2n_kem_group(kem));
                curves.chain(kem_groups).collect::<Vec<GroupInformation>>()
            })
            .collect();
        let mut groups: Vec<GroupInformation> = groups.into_iter().collect();
        groups.sort_by_key(|group| group.iana_description);
        groups
    }

    /// return all of the signatures defined in any s2n-tls security policy
    fn all_available_signatures() -> Vec<SignatureSchemeInformation> {
        let sigs: HashSet<SignatureSchemeInformation> =
            s2n_tls_sys_internal::security_policy_table()
                .iter()
                .flat_map(|sp| {
                    let sp = unsafe { &*sp.security_policy };
                    sp.signatures()
                        .iter()
                        .map(|sig| SignatureSchemeInformation::from_s2n_signature_scheme(sig))
                })
                .collect();
        let mut sigs: Vec<SignatureSchemeInformation> = sigs.into_iter().collect();
        sigs.sort_by_key(|sig| sig.description);
        sigs
    }

    #[test]
    fn all_ciphers_in_static_list() {
        let ciphers = all_available_ciphers();
        assert_eq!(&ciphers, CIPHERS_AVAILABLE_IN_S2N);
    }

    #[test]
    fn all_groups_in_static_list() {
        let groups = all_available_groups();
        assert_eq!(&groups, GROUPS_AVAILABLE_IN_S2N);
    }

    #[test]
    fn all_signature_schemes_in_static_list() {
        let schemes = all_available_signatures();
        assert_eq!(&schemes, SIGNATURE_SCHEMES_AVAILABLE_IN_S2N);
    }

    #[test]
    fn index_and_name_lookup() {
        for (index, item) in CIPHERS_AVAILABLE_IN_S2N.iter().enumerate() {
            let returned_index = TlsParam::Cipher
                .description_to_index(item.iana_description)
                .unwrap();
            let returned_description = TlsParam::Cipher
                .index_to_description(returned_index)
                .unwrap();
            assert_eq!(returned_description, item.iana_description);
            assert_eq!(returned_index, index);
        }

        for (index, item) in GROUPS_AVAILABLE_IN_S2N.iter().enumerate() {
            let returned_index = TlsParam::Group
                .description_to_index(item.iana_description)
                .unwrap();
            let returned_description = TlsParam::Group
                .index_to_description(returned_index)
                .unwrap();
            assert_eq!(returned_description, item.iana_description);
            assert_eq!(returned_index, index);
        }

        for (index, item) in SIGNATURE_SCHEMES_AVAILABLE_IN_S2N.iter().enumerate() {
            let returned_index = TlsParam::SignatureScheme
                .description_to_index(item.description)
                .unwrap();
            let returned_description = TlsParam::SignatureScheme
                .index_to_description(returned_index)
                .unwrap();
            assert_eq!(returned_description, item.description);
            assert_eq!(returned_index, index);
        }
    }
}
