// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module contains the static lists of all possible values emitted by the
//! s2n-tls "getter" APIs. These static lists are important because they allow us
//! to maintain an array of atomic counters instead of having to resort to a hashmap

// allowing unused lints while crate is under development, many of these structs
// won't be used until the subscriber is actually implemented
#![allow(unused)]

#[cfg(test)]
use std::ffi::c_char;

#[cfg(test)]
use s2n_tls_sys_internal::{
    s2n_cipher_suite, s2n_ecc_named_curve, s2n_kem_group, s2n_signature_scheme,
};
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Cipher {
    iana_description: &'static str,
    iana_value: [u8; 2],
    openssl_name: &'static str,
}

impl Cipher {
    const fn new(
        iana_description: &'static str,
        iana_value: [u8; 2],
        openssl_name: &'static str,
    ) -> Self {
        Self {
            openssl_name,
            iana_description,
            iana_value,
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
pub(crate) struct Group {
    iana_description: &'static str,
    iana_value: u16,
}

impl Group {
    const fn new(iana_description: &'static str, iana_value: u16) -> Self {
        Self {
            iana_description,
            iana_value,
        }
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
pub(crate) struct SignatureScheme {
    iana_description: &'static str,
    iana_value: u16,
}

impl SignatureScheme {
    const fn new(iana_description: &'static str, iana_value: u16) -> Self {
        Self {
            iana_description,
            iana_value,
        }
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

/// We are required to track OpenSSL naming because that is what 
#[rustfmt::skip]
pub(crate) const CIPHERS_AVAILABLE_IN_S2N: &[Cipher] = &[
    Cipher::new("TLS_AES_128_GCM_SHA256", [19, 1], "TLS_AES_128_GCM_SHA256" ),
    Cipher::new("TLS_AES_256_GCM_SHA384", [19, 2], "TLS_AES_256_GCM_SHA384" ),
    Cipher::new("TLS_CHACHA20_POLY1305_SHA256", [19, 3], "TLS_CHACHA20_POLY1305_SHA256" ),
    Cipher::new("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", [0, 22], "DHE-RSA-DES-CBC3-SHA" ),
    Cipher::new("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", [0, 51], "DHE-RSA-AES128-SHA" ),
    Cipher::new("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", [0, 103], "DHE-RSA-AES128-SHA256" ),
    Cipher::new("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", [0, 158], "DHE-RSA-AES128-GCM-SHA256" ),
    Cipher::new("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", [0, 57], "DHE-RSA-AES256-SHA" ),
    Cipher::new("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", [0, 107], "DHE-RSA-AES256-SHA256" ),
    Cipher::new("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", [0, 159], "DHE-RSA-AES256-GCM-SHA384" ),
    Cipher::new("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", [204, 170], "DHE-RSA-CHACHA20-POLY1305" ),
    Cipher::new("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", [192, 9], "ECDHE-ECDSA-AES128-SHA" ),
    Cipher::new("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", [192, 35], "ECDHE-ECDSA-AES128-SHA256" ),
    Cipher::new("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", [192, 43], "ECDHE-ECDSA-AES128-GCM-SHA256" ),
    Cipher::new("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", [192, 10], "ECDHE-ECDSA-AES256-SHA" ),
    Cipher::new("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", [192, 36], "ECDHE-ECDSA-AES256-SHA384" ),
    Cipher::new("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", [192, 44], "ECDHE-ECDSA-AES256-GCM-SHA384" ),
    Cipher::new("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", [204, 169], "ECDHE-ECDSA-CHACHA20-POLY1305" ),
    Cipher::new("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", [192, 18], "ECDHE-RSA-DES-CBC3-SHA" ),
    Cipher::new("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", [192, 19], "ECDHE-RSA-AES128-SHA" ),
    Cipher::new("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", [192, 39], "ECDHE-RSA-AES128-SHA256" ),
    Cipher::new("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", [192, 47], "ECDHE-RSA-AES128-GCM-SHA256" ),
    Cipher::new("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", [192, 20], "ECDHE-RSA-AES256-SHA" ),
    Cipher::new("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", [192, 40], "ECDHE-RSA-AES256-SHA384" ),
    Cipher::new("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", [192, 48], "ECDHE-RSA-AES256-GCM-SHA384" ),
    Cipher::new("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", [204, 168], "ECDHE-RSA-CHACHA20-POLY1305" ),
    Cipher::new("TLS_ECDHE_RSA_WITH_RC4_128_SHA", [192, 17], "ECDHE-RSA-RC4-SHA" ),
    Cipher::new("TLS_NULL_WITH_NULL_NULL", [0, 0], "TLS_NULL_WITH_NULL_NULL" ),
    Cipher::new("TLS_RSA_WITH_3DES_EDE_CBC_SHA", [0, 10], "DES-CBC3-SHA" ),
    Cipher::new("TLS_RSA_WITH_AES_128_CBC_SHA", [0, 47], "AES128-SHA" ),
    Cipher::new("TLS_RSA_WITH_AES_128_CBC_SHA256", [0, 60], "AES128-SHA256" ),
    Cipher::new("TLS_RSA_WITH_AES_128_GCM_SHA256", [0, 156], "AES128-GCM-SHA256" ),
    Cipher::new("TLS_RSA_WITH_AES_256_CBC_SHA", [0, 53], "AES256-SHA" ),
    Cipher::new("TLS_RSA_WITH_AES_256_CBC_SHA256", [0, 61], "AES256-SHA256" ),
    Cipher::new("TLS_RSA_WITH_AES_256_GCM_SHA384", [0, 157], "AES256-GCM-SHA384" ),
    Cipher::new("TLS_RSA_WITH_RC4_128_MD5", [0, 4], "RC4-MD5" ),
    Cipher::new("TLS_RSA_WITH_RC4_128_SHA", [0, 5], "RC4-SHA"),
];

pub(crate) const GROUPS_AVAILABLE_IN_S2N: &[Group] = &[
    Group::new("MLKEM1024", 514),
    Group::new("SecP256r1Kyber768Draft00", 25498),
    Group::new("SecP256r1MLKEM768", 4587),
    Group::new("SecP384r1MLKEM1024", 4589),
    Group::new("X25519Kyber768Draft00", 25497),
    Group::new("X25519MLKEM768", 4588),
    Group::new("secp256r1", 23),
    Group::new("secp256r1_kyber-512-r3", 12090),
    Group::new("secp384r1", 24),
    Group::new("secp384r1_kyber-768-r3", 12092),
    Group::new("secp521r1", 25),
    Group::new("secp521r1_kyber-1024-r3", 12093),
    Group::new("x25519", 29),
    Group::new("x25519_kyber-512-r3", 12089),
];

pub(crate) const SIGNATURE_SCHEMES_AVAILABLE_IN_S2N: &[SignatureScheme] = &[
    SignatureScheme::new("ecdsa_sha1", 515),
    SignatureScheme::new("ecdsa_sha256", 1027),
    SignatureScheme::new("ecdsa_sha384", 1283),
    SignatureScheme::new("ecdsa_sha512", 1539),
    SignatureScheme::new("legacy_ecdsa_sha224", 771),
    SignatureScheme::new("legacy_rsa_md5_sha1", 65535),
    SignatureScheme::new("legacy_rsa_sha224", 769),
    SignatureScheme::new("mldsa44", 2308),
    SignatureScheme::new("mldsa65", 2309),
    SignatureScheme::new("mldsa87", 2310),
    SignatureScheme::new("rsa_pkcs1_sha1", 513),
    SignatureScheme::new("rsa_pkcs1_sha256", 1025),
    SignatureScheme::new("rsa_pkcs1_sha384", 1281),
    SignatureScheme::new("rsa_pkcs1_sha512", 1537),
    SignatureScheme::new("rsa_pss_pss_sha256", 2057),
    SignatureScheme::new("rsa_pss_pss_sha384", 2058),
    SignatureScheme::new("rsa_pss_pss_sha512", 2059),
    SignatureScheme::new("rsa_pss_rsae_sha256", 2052),
    SignatureScheme::new("rsa_pss_rsae_sha384", 2053),
    SignatureScheme::new("rsa_pss_rsae_sha512", 2054),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// return all of the ciphers defined in any s2n-tls security policy
    fn all_available_ciphers() -> Vec<Cipher> {
        let ciphers: HashSet<Cipher> = s2n_tls_sys_internal::security_policy_table()
            .iter()
            .flat_map(|sp| {
                let sp = unsafe { &*sp.security_policy };
                let names: Vec<Cipher> = sp
                    .ciphers()
                    .iter()
                    .cloned()
                    .map(Cipher::from_s2n_cipher_suite)
                    .collect();
                names
            })
            .collect();
        let mut ciphers: Vec<Cipher> = ciphers.into_iter().collect();
        ciphers.sort_by_key(|cipher| cipher.iana_description);
        ciphers
    }

    /// return all of the groups defined in any s2n-tls security policy
    fn all_available_groups() -> Vec<Group> {
        let groups: HashSet<Group> = s2n_tls_sys_internal::security_policy_table()
            .iter()
            .flat_map(|sp| {
                let sp = unsafe { &*sp.security_policy };
                let curves = sp
                    .curves()
                    .iter()
                    .map(|curve| Group::from_s2n_ecc_curve(curve));
                let kem_groups = sp.kems().iter().map(|kem| Group::from_s2n_kem_group(kem));
                curves.chain(kem_groups).collect::<Vec<Group>>()
            })
            .collect();
        let mut groups: Vec<Group> = groups.into_iter().collect();
        groups.sort_by_key(|group| group.iana_description);
        groups
    }

    /// return all of the signatures defined in any s2n-tls security policy
    fn all_available_signatures() -> Vec<SignatureScheme> {
        let sigs: HashSet<SignatureScheme> = s2n_tls_sys_internal::security_policy_table()
            .iter()
            .flat_map(|sp| {
                let sp = unsafe { &*sp.security_policy };
                sp.signatures()
                    .iter()
                    .map(|sig| SignatureScheme::from_s2n_signature_scheme(sig))
            })
            .collect();
        let mut sigs: Vec<SignatureScheme> = sigs.into_iter().collect();
        sigs.sort_by_key(|group| group.iana_description);
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
}
