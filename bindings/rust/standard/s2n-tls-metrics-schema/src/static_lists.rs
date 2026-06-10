// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module contains the static lists of all possible values emitted by the
//! s2n-tls "getter" APIs. These static lists are important because they allow us
//! to maintain an array of atomic counters instead of having to resort to a hashmap.

use std::{fmt::Display, str::FromStr};

use s2n_codec::zerocopy::U16;
use serde_with::{DeserializeAs, SerializeAs, serde_as};
use zerocopy::{FromBytes, Immutable, Unaligned};

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

pub const GROUP_COUNT: usize = GROUPS_AVAILABLE_IN_S2N.len();
pub const CIPHER_COUNT: usize = CIPHERS_AVAILABLE_IN_S2N.len();
pub const SIGNATURE_COUNT: usize = SIGNATURE_SCHEMES_AVAILABLE_IN_S2N.len();
pub const PROTOCOL_COUNT: usize = VERSIONS_AVAILABLE_IN_S2N.len();

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

/// `serde_as` helper: encode `zerocopy::U16` as a native-endian `u16`.
/// Shared by `Version`, `Group`, and `Signature`, whose wire form is the
/// host-order numeric id returned by `.get()`.
pub(crate) struct ZerocopyU16;

impl SerializeAs<U16> for ZerocopyU16 {
    fn serialize_as<S: serde::Serializer>(value: &U16, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(value.get())
    }
}

impl<'de> DeserializeAs<'de, U16> for ZerocopyU16 {
    fn deserialize_as<D: serde::Deserializer<'de>>(deserializer: D) -> Result<U16, D::Error> {
        <u16 as serde::Deserialize>::deserialize(deserializer).map(U16::new)
    }
}

/// A TLS parameter type whose values can be enumerated at compile time,
/// giving each value a stable slot index in `[0, N)` for the counter
/// abstraction to use. The trait only constrains the slot bijection;
/// separate concerns (`Display`, serde, `FromStr`) are required at the
/// impl sites that use them.
pub trait FiniteCounter<const N: usize>: Copy + PartialEq {
    /// All values of `Self` that the counter recognizes. Every element is
    /// assigned a stable slot index equal to its position in this array.
    const ELEMENTS: [Self; N];

    /// Slot index for this element, or `None` if not in [`Self::ELEMENTS`].
    fn slot_from_key(&self) -> Option<usize> {
        Self::ELEMENTS.iter().position(|e| e == self)
    }

    /// Element at `slot`, or `None` if out of range.
    fn key_from_slot(slot: usize) -> Option<Self> {
        Self::ELEMENTS.get(slot).copied()
    }
}

impl FiniteCounter<CIPHER_COUNT> for Cipher {
    const ELEMENTS: [Cipher; CIPHER_COUNT] = {
        let mut out = [Cipher([0, 0]); CIPHER_COUNT];
        let mut i = 0;
        while i < CIPHER_COUNT {
            out[i] = CIPHERS_AVAILABLE_IN_S2N[i].cipher;
            i += 1;
        }
        out
    };
}

impl FromStr for Cipher {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CIPHERS_AVAILABLE_IN_S2N
            .iter()
            .find(|info| info.iana_description == s)
            .map(|info| info.cipher)
            .ok_or(())
    }
}

impl FiniteCounter<PROTOCOL_COUNT> for Version {
    const ELEMENTS: [Version; PROTOCOL_COUNT] = {
        let mut out = [Version(U16::new(0)); PROTOCOL_COUNT];
        let mut i = 0;
        while i < PROTOCOL_COUNT {
            out[i] = Version(U16::new(VERSIONS_AVAILABLE_IN_S2N[i].iana_value));
            i += 1;
        }
        out
    };
}

impl FromStr for Version {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        VERSIONS_AVAILABLE_IN_S2N
            .iter()
            .find(|info| info.description == s)
            .map(|info| Version(U16::new(info.iana_value)))
            .ok_or(())
    }
}

impl FiniteCounter<GROUP_COUNT> for Group {
    const ELEMENTS: [Group; GROUP_COUNT] = {
        let mut out = [Group(U16::new(0)); GROUP_COUNT];
        let mut i = 0;
        while i < GROUP_COUNT {
            out[i] = GROUPS_AVAILABLE_IN_S2N[i].group;
            i += 1;
        }
        out
    };
}

impl FromStr for Group {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        GROUPS_AVAILABLE_IN_S2N
            .iter()
            .find(|info| info.iana_description == s)
            .map(|info| info.group)
            .ok_or(())
    }
}

impl FiniteCounter<SIGNATURE_COUNT> for Signature {
    const ELEMENTS: [Signature; SIGNATURE_COUNT] = {
        let mut out = [Signature(U16::new(0)); SIGNATURE_COUNT];
        let mut i = 0;
        while i < SIGNATURE_COUNT {
            out[i] = SIGNATURE_SCHEMES_AVAILABLE_IN_S2N[i].signature;
            i += 1;
        }
        out
    };
}

impl FromStr for Signature {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SIGNATURE_SCHEMES_AVAILABLE_IN_S2N
            .iter()
            .find(|info| info.description == s)
            .map(|info| info.signature)
            .ok_or(())
    }
}

impl FiniteCounter<DEFINED_ALERTS_COUNT> for Alert {
    const ELEMENTS: [Self; DEFINED_ALERTS_COUNT] = Alert::DEFINED_ALERTS;
}

#[serde_as]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    FromBytes,
    Immutable,
    Unaligned,
    serde::Serialize,
    serde::Deserialize,
)]
#[repr(C)]
pub struct Version(#[serde_as(as = "ZerocopyU16")] pub s2n_codec::zerocopy::U16);

impl Version {
    pub const SSL_V3: Version = Version(U16::new(0x0300));
    pub const TLS_1_0: Version = Version(U16::new(0x0301));
    pub const TLS_1_1: Version = Version(U16::new(0x0302));
    pub const TLS_1_2: Version = Version(U16::new(0x0303));
    pub const TLS_1_3: Version = Version(U16::new(0x0304));

    pub fn known_description(&self) -> Option<&'static str> {
        match *self {
            Self::SSL_V3 => Some("SSLv3"),
            Self::TLS_1_0 => Some("TLSv1_0"),
            Self::TLS_1_1 => Some("TLSv1_1"),
            Self::TLS_1_2 => Some("TLSv1_2"),
            Self::TLS_1_3 => Some("TLSv1_3"),
            _ => None,
        }
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.known_description() {
            Some(name) => f.write_str(name),
            None => write!(f, "unknown_version_0x{:04x}", self.0.get()),
        }
    }
}

impl<'a> s2n_codec::DecoderValue<'a> for Version {
    fn decode(bytes: s2n_codec::DecoderBuffer<'a>) -> s2n_codec::DecoderBufferResult<'a, Self> {
        let (value, bytes) = bytes.decode()?;
        Ok((Self(value), bytes))
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    FromBytes,
    Immutable,
    Unaligned,
    serde::Serialize,
    serde::Deserialize,
)]
#[repr(C)]
pub struct Cipher(pub [u8; 2]);

impl Cipher {
    #[allow(dead_code)]
    pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: Self = Cipher([0, 255]);

    pub const TLS_AES_128_GCM_SHA256: Self = Cipher([0x13, 0x01]);
    pub const TLS_AES_256_GCM_SHA384: Self = Cipher([0x13, 0x02]);
    pub const TLS_CHACHA20_POLY1305_SHA256: Self = Cipher([0x13, 0x03]);
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Self = Cipher([0xC0, 0x2B]);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: Self = Cipher([0xC0, 0x2C]);
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Self = Cipher([0xC0, 0x2F]);
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: Self = Cipher([0xC0, 0x30]);

    pub fn known_description(&self) -> Option<&'static str> {
        CIPHERS_AVAILABLE_IN_S2N
            .iter()
            .find(|info| info.cipher == *self)
            .map(|info| info.iana_description)
    }

    pub fn from_openssl_name(name: &str) -> Option<Self> {
        CIPHERS_AVAILABLE_IN_S2N
            .iter()
            .find(|info| info.openssl_name == name)
            .map(|info| info.cipher)
    }
}

impl Display for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.known_description() {
            Some(name) => f.write_str(name),
            None => {
                let [hi, lo] = self.0;
                let id = ((hi as u16) << 8) | (lo as u16);
                write!(f, "unknown_cipher_0x{id:04x}")
            }
        }
    }
}

#[serde_as]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    FromBytes,
    Immutable,
    Unaligned,
    serde::Serialize,
    serde::Deserialize,
)]
#[repr(C)]
pub struct Signature(#[serde_as(as = "ZerocopyU16")] pub s2n_codec::zerocopy::U16);

#[allow(non_upper_case_globals)]
impl Signature {
    pub const rsa_pss_rsae_sha256: Self = Signature(U16::new(0x0804));
    pub const rsa_pss_rsae_sha384: Self = Signature(U16::new(0x0805));
    pub const rsa_pss_rsae_sha512: Self = Signature(U16::new(0x0806));

    pub const rsa_pss_pss_sha256: Self = Signature(U16::new(0x0809));
    pub const rsa_pss_pss_sha384: Self = Signature(U16::new(0x080A));
    pub const rsa_pss_pss_sha512: Self = Signature(U16::new(0x080B));

    pub const ecdsa_secp256r1_sha256: Self = Signature(U16::new(0x0403));
    pub const ecdsa_secp384r1_sha384: Self = Signature(U16::new(0x0503));
    pub const ecdsa_secp521r1_sha512: Self = Signature(U16::new(0x0603));

    #[allow(dead_code)]
    pub const mldsa44: Self = Signature(U16::new(0x0904));
    #[allow(dead_code)]
    pub const mldsa65: Self = Signature(U16::new(0x0905));
    pub const mldsa87: Self = Signature(U16::new(0x0906));

    pub fn known_description(&self) -> Option<&'static str> {
        SIGNATURE_SCHEMES_AVAILABLE_IN_S2N
            .iter()
            .find(|info| info.signature == *self)
            .map(|info| info.description)
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.known_description() {
            Some(name) => f.write_str(name),
            None => write!(f, "unknown_signature_0x{:04x}", self.0.get()),
        }
    }
}

#[serde_as]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    FromBytes,
    Immutable,
    Unaligned,
    serde::Serialize,
    serde::Deserialize,
)]
#[repr(C)]
pub struct Group(#[serde_as(as = "ZerocopyU16")] pub s2n_codec::zerocopy::U16);

#[allow(non_upper_case_globals)]
impl Group {
    pub const x25519: Self = Group(U16::new(29));
    pub const secp256r1: Self = Group(U16::new(23));
    pub const secp384r1: Self = Group(U16::new(24));
    pub const secp521r1: Self = Group(U16::new(25));

    pub const SecP256r1MLKEM768: Self = Group(U16::new(4587));
    pub const X25519MLKEM768: Self = Group(U16::new(4588));
    pub const SecP384r1MLKEM1024: Self = Group(U16::new(4589));

    pub const MLKEM1024: Self = Group(U16::new(514));

    pub fn known_description(&self) -> Option<&'static str> {
        GROUPS_AVAILABLE_IN_S2N
            .iter()
            .find(|info| info.group == *self)
            .map(|info| info.iana_description)
    }
}

impl Display for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.known_description() {
            Some(name) => f.write_str(name),
            None => write!(f, "unknown_group_0x{:04x}", self.0.get()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VersionInformation {
    pub description: &'static str,
    pub iana_value: u16,
}

impl VersionInformation {
    pub const fn new(description: &'static str, iana_value: u16) -> Self {
        Self {
            description,
            iana_value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CipherInformation {
    pub cipher: Cipher,
    pub iana_description: &'static str,
    pub openssl_name: &'static str,
}

impl CipherInformation {
    pub const fn new(
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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupInformation {
    pub iana_description: &'static str,
    pub group: Group,
}

impl GroupInformation {
    pub const fn new(iana_description: &'static str, iana_value: u16) -> Self {
        Self {
            iana_description,
            group: Group(U16::new(iana_value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignatureSchemeInformation {
    pub description: &'static str,
    pub signature: Signature,
}

impl SignatureSchemeInformation {
    pub const fn new(iana_description: &'static str, iana_value: u16) -> Self {
        Self {
            description: iana_description,
            signature: Signature(U16::new(iana_value)),
        }
    }
}

/// Represents a TLS alert
/// 
/// Most elements of this struct are code-generated from the relevant IANA csv
/// ```
/// use s2n_tls_metrics_schema::static_lists::Alert;
/// 
/// // named constant
/// let alert = Alert::CLOSE_NOTIFY;
/// 
/// // string description
/// assert_eq!(Alert::CLOSE_NOTIFY.get_description(), Some("close_notify"));
/// 
/// // domain of all defined alerts
/// assert_eq!(Alert::DEFINED_ALERTS.len(), 30);
/// ```
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct Alert(pub u8);
include!(concat!(env!("OUT_DIR"), "/alerts_generated.rs"));

impl Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.get_description() {
            Some(name) => f.write_str(name),
            None => write!(f, "unknown_alert_{}", self.0),
        }
    }
}

impl FromStr for Alert {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::DEFINED_ALERTS
            .iter()
            .find(|a| a.get_description() == Some(s))
            .copied()
            .ok_or(())
    }
}

pub const DEFINED_ALERTS_COUNT: usize = Alert::DEFINED_ALERTS.len();


pub const VERSIONS_AVAILABLE_IN_S2N: [VersionInformation; 5] = [
    VersionInformation::new("SSLv3", 0x0300),
    VersionInformation::new("TLSv1_0", 0x0301),
    VersionInformation::new("TLSv1_1", 0x0302),
    VersionInformation::new("TLSv1_2", 0x0303),
    VersionInformation::new("TLSv1_3", 0x0304),
];

#[rustfmt::skip]
pub const CIPHERS_AVAILABLE_IN_S2N: [CipherInformation; 37] = [
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

pub const GROUPS_AVAILABLE_IN_S2N: [GroupInformation; 8] = [
    GroupInformation::new("MLKEM1024", 514),
    GroupInformation::new("SecP256r1MLKEM768", 4587),
    GroupInformation::new("SecP384r1MLKEM1024", 4589),
    GroupInformation::new("X25519MLKEM768", 4588),
    GroupInformation::new("secp256r1", 23),
    GroupInformation::new("secp384r1", 24),
    GroupInformation::new("secp521r1", 25),
    GroupInformation::new("x25519", 29),
];

pub const SIGNATURE_SCHEMES_AVAILABLE_IN_S2N: [SignatureSchemeInformation; 20] = [
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

    #[test]
    fn display_fallback_for_unknown_elements() {
        assert_eq!(Cipher([0xFF, 0xFF]).to_string(), "unknown_cipher_0xffff");
        assert_eq!(
            Version(U16::new(0x9999)).to_string(),
            "unknown_version_0x9999"
        );
        assert_eq!(Group(U16::new(0x9999)).to_string(), "unknown_group_0x9999");
        assert_eq!(
            Signature(U16::new(0x9999)).to_string(),
            "unknown_signature_0x9999"
        );
    }

    #[test]
    fn cipher_constants_match() {
        let cases: &[(Cipher, &str)] = &[
            (Cipher::TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"),
            (Cipher::TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"),
            (
                Cipher::TLS_CHACHA20_POLY1305_SHA256,
                "TLS_CHACHA20_POLY1305_SHA256",
            ),
            (
                Cipher::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            ),
            (
                Cipher::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            ),
            (
                Cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            ),
            (
                Cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ),
        ];
        for (constant, expected_name) in cases {
            assert_eq!(constant.known_description().unwrap(), *expected_name);
        }
    }

    #[test]
    fn group_constants_match() {
        let cases: &[(Group, &str)] = &[
            (Group::x25519, "x25519"),
            (Group::secp256r1, "secp256r1"),
            (Group::secp384r1, "secp384r1"),
            (Group::secp521r1, "secp521r1"),
            (Group::SecP256r1MLKEM768, "SecP256r1MLKEM768"),
            (Group::X25519MLKEM768, "X25519MLKEM768"),
            (Group::SecP384r1MLKEM1024, "SecP384r1MLKEM1024"),
            (Group::MLKEM1024, "MLKEM1024"),
        ];
        for (constant, expected_name) in cases {
            assert_eq!(constant.known_description().unwrap(), *expected_name);
        }
    }

    #[test]
    fn signature_constants_match() {
        let cases: &[(Signature, &str)] = &[
            (Signature::rsa_pss_rsae_sha256, "rsa_pss_rsae_sha256"),
            (Signature::rsa_pss_rsae_sha384, "rsa_pss_rsae_sha384"),
            (Signature::rsa_pss_rsae_sha512, "rsa_pss_rsae_sha512"),
            (Signature::rsa_pss_pss_sha256, "rsa_pss_pss_sha256"),
            (Signature::rsa_pss_pss_sha384, "rsa_pss_pss_sha384"),
            (Signature::rsa_pss_pss_sha512, "rsa_pss_pss_sha512"),
            (Signature::ecdsa_secp256r1_sha256, "ecdsa_sha256"),
            (Signature::ecdsa_secp384r1_sha384, "ecdsa_sha384"),
            (Signature::ecdsa_secp521r1_sha512, "ecdsa_sha512"),
            (Signature::mldsa44, "mldsa44"),
            (Signature::mldsa65, "mldsa65"),
            (Signature::mldsa87, "mldsa87"),
        ];
        for (constant, expected_name) in cases {
            assert_eq!(constant.known_description().unwrap(), *expected_name);
        }
    }
}
