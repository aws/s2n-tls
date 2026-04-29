// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A minimal X509 parser to efficiently extract the limited information that we
//! care about.
//!
//! ### Why not get this from s2n-tls?
//!
//! C/Rust FFI gets you the worst of both worlds. It would require defining all
//! of the enums on the C side, and threading that access through into the rust
//! bindings. Additionally, most of these fields are not currently public. With
//! the current state of the C library, it seems better to have a strongly encapsulated
//! chunk of complexity in the non-security critical component, rather than pushing
//! that down into the TLS layer.
//!
//! Additionally, this keeps open a future where the metrics subscriber is also
//! used by AWS-LC's libssl.
//!
//! ### Why not use an existing library?
//!
//! Performance.
//!
//! These are numbers from a very rough benchmark that I did 2026-04-17.
//!
//! |    Parser   | Per-cert |
//! |-------------|----------|
//! | webpki      |  0.333µs (no key/sig) |
//! | s2n-codec   |  0.222µs |
//! | x509-parser |  5.7µs |
//! | x509-cert   | 13.8µs |
//! | aws-lc      | 21.7µs |
//!
//! Existing cert parsing libraries are roughly 25x slower than this custom implementation.
//! webpki is very speedy, but doesn't pull out the key/signature information that
//! we need.
//!
//! While 5.7 us may seem pretty fast, in an mTLS case we might end up parsing 6
//! cert chains per handshake, and adding 34.2 us would be a nearly 10% performance
//! hit.

// temporarily allowing dead_code, because this isn't yet integrated into the actual
// metrics subscriber
#![allow(dead_code)]

use s2n_codec::decoder::DecoderError;

/// Parsed cert fields from the TBSCertificate.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedCertContent {
    /// The serial of the certificate, allowing it to be uniquely identified
    pub serial: Vec<u8>,
    /// The issuer (CA) of the certificate, e.g. `Amazon Root CA 1`
    pub issuer: String,
    /// The common name of the certificate subject, e.g. `sqs.us-east-2.amazonaws.com`
    pub common_name: String,
    pub key_type: KeyType,
    pub signature: SignatureAlgorithm,
}

/// KeyType can be decoded from an AlgorithmIdentifier element of an X509 certificate
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyType {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    RsaPss2048,
    RsaPss3072,
    RsaPss4096,
    Secp256r1,
    Secp384r1,
    Secp521r1,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    RsaPkcsSha1,
    RsaPkcsSha256,
    RsaPkcsSha384,
    RsaPkcsSha512,
    /// NOTE: RSA-PSS encodes the hash algorithm in the AlgorithmIdentifier
    /// parameters (RSASSA-PSS-params), not in the OID itself. We currently
    /// only parse the OID, so the hash (e.g. SHA256) is not reported.
    RsaPss,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    Unknown,
}

impl SignatureAlgorithm {
    fn from_oid(oid: &[u8]) -> Self {
        // implemented inside der_codec where OID constants are in scope
        der_codec::signature_from_oid(oid)
    }
}

mod der_codec {
    use core::mem::size_of;
    use s2n_codec::{DecoderBuffer, DecoderBufferResult, DecoderError, DecoderValue};

    use const_oid::ObjectIdentifier;

    // DER tag constants
    const TAG_SEQUENCE: u8 = 0x30;
    const TAG_SET: u8 = 0x31;
    const TAG_INTEGER: u8 = 0x02;
    const TAG_OID: u8 = 0x06;
    const TAG_BIT_STRING: u8 = 0x03;
    const TAG_CONTEXT_0: u8 = 0xa0; // [0] EXPLICIT (certificate version)
    // X.520 DirectoryString types (RFC 5280 §4.1.2.4)
    /// Full Unicode via UTF-8. The modern default for new certificates.
    const TAG_UTF8_STRING: u8 = 0x0c;
    /// Restricted to A-Z, a-z, 0-9, space, and ' ( ) + , - . / : = ?
    const TAG_PRINTABLE_STRING: u8 = 0x13;
    /// ASCII (0x00-0x7F). Used for email addresses and domain names.
    const TAG_IA5_STRING: u8 = 0x16;

    // Signature algorithm OIDs
    const OID_RSA_PKCS_SHA1: &[u8] =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5").as_bytes();
    const OID_RSA_PKCS_SHA256: &[u8] =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11").as_bytes();
    const OID_RSA_PKCS_SHA384: &[u8] =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12").as_bytes();
    const OID_RSA_PKCS_SHA512: &[u8] =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13").as_bytes();
    const OID_RSA_PSS: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10").as_bytes();
    const OID_ECDSA_SHA256: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2").as_bytes();
    const OID_ECDSA_SHA384: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3").as_bytes();
    const OID_ECDSA_SHA512: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4").as_bytes();

    // Key algorithm OIDs
    const OID_RSA_KEY: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1").as_bytes();
    const OID_RSA_PSS_KEY: &[u8] = OID_RSA_PSS;
    const OID_EC_PUBLIC_KEY: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1").as_bytes();

    // EC named curve OIDs
    const OID_SECP256R1: &[u8] = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7").as_bytes();
    const OID_SECP384R1: &[u8] = ObjectIdentifier::new_unwrap("1.3.132.0.34").as_bytes();
    const OID_SECP521R1: &[u8] = ObjectIdentifier::new_unwrap("1.3.132.0.35").as_bytes();

    // Common Name OID
    const OID_CN: &[u8] = ObjectIdentifier::new_unwrap("2.5.4.3").as_bytes();

    pub fn signature_from_oid(oid: &[u8]) -> super::SignatureAlgorithm {
        use super::SignatureAlgorithm;
        match oid {
            OID_RSA_PKCS_SHA1 => SignatureAlgorithm::RsaPkcsSha1,
            OID_RSA_PKCS_SHA256 => SignatureAlgorithm::RsaPkcsSha256,
            OID_RSA_PKCS_SHA384 => SignatureAlgorithm::RsaPkcsSha384,
            OID_RSA_PKCS_SHA512 => SignatureAlgorithm::RsaPkcsSha512,
            OID_RSA_PSS => SignatureAlgorithm::RsaPss,
            OID_ECDSA_SHA256 => SignatureAlgorithm::EcdsaSha256,
            OID_ECDSA_SHA384 => SignatureAlgorithm::EcdsaSha384,
            OID_ECDSA_SHA512 => SignatureAlgorithm::EcdsaSha512,
            _ => SignatureAlgorithm::Unknown,
        }
    }

    /// A DER-encoded length field.
    ///
    /// DER length encoding:
    /// - `< 0x80`: short form — the byte IS the length (0–127)
    /// - `>= 0x80`: long form — low 7 bits = number of subsequent bytes
    ///   encoding the length as a big-endian unsigned integer
    /// - `0x80` (indefinite length) is invalid in DER
    struct DerLength(usize);

    enum DerLengthEncoding {
        Short,
        Long,
        Indefinite,
    }

    impl DerLengthEncoding {
        const SENTINEL_VALUE: u8 = 0b10000000;
        const LONG_FORM_MASK: u8 = 0b01111111;
        fn from_first_byte(first_length_byte: u8) -> Self {
            if first_length_byte < Self::SENTINEL_VALUE {
                Self::Short
            } else if first_length_byte > Self::SENTINEL_VALUE {
                Self::Long
            } else {
                Self::Indefinite
            }
        }
    }

    impl<'a> DecoderValue<'a> for DerLength {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            let first = buffer.peek_byte(0)?;
            let encoding = DerLengthEncoding::from_first_byte(first);
            match encoding {
                DerLengthEncoding::Short => {
                    let (length, buffer) = buffer.decode::<u8>()?;
                    Ok((DerLength(length as usize), buffer))
                }
                DerLengthEncoding::Long => {
                    // the number of bytes in the length encoding
                    let (length_encoding_size, buffer) = {
                        let (size, buffer) = buffer.decode::<u8>()?;
                        let size = (size & DerLengthEncoding::LONG_FORM_MASK) as usize;
                        if size > size_of::<usize>() {
                            return Err(s2n_codec::decoder::DecoderError::LengthCapacityExceeded);
                        }
                        (size, buffer)
                    };
                    let (length, buffer) = {
                        let (len_bytes, buffer) = buffer.decode_slice(length_encoding_size)?;
                        let raw = len_bytes.into_less_safe_slice();
                        let mut buf = [0u8; size_of::<usize>()];
                        let start = size_of::<usize>()
                            .checked_sub(raw.len())
                            .ok_or(DecoderError::LengthCapacityExceeded)?;
                        buf.get_mut(start..)
                            .ok_or(DecoderError::LengthCapacityExceeded)?
                            .copy_from_slice(raw);
                        (usize::from_be_bytes(buf), buffer)
                    };
                    // X.690 §10.1: DER requires minimal length encoding.
                    // Values < 0x80 must use the short (single-byte) form.
                    if length < DerLengthEncoding::SENTINEL_VALUE as usize {
                        return Err(DecoderError::InvariantViolation(
                            "non-minimal length encoding",
                        ));
                    }
                    Ok((DerLength(length), buffer))
                }
                DerLengthEncoding::Indefinite => {
                    // "indefinite" form of length encoding, not allowed for DER
                    // > The definite form of length encoding shall be used, encoded in the minimum number of octets.
                    // > 10.1 - Distinguished Encoding Rules: Length Forms
                    // > ITU-T X.690
                    Err(DecoderError::InvariantViolation(
                        "indefinite length encoding not allowed",
                    ))
                }
            }
        }
    }

    /// A DER tag-length-value: (tag, content bytes).
    ///
    /// Prefer to use strongly typed containers like [`DerSequence`], [`DerSet`],
    /// etc for decoding ease.
    ///
    /// Developer note: I previously tried to parse tag into an enum, but the 10-ish
    /// way match statement nearly doubled the cost of cert parsing.
    struct Tlv<'a> {
        tag: u8,
        content: &'a [u8],
    }

    impl<'a> DecoderValue<'a> for Tlv<'a> {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            let (tag, buffer) = buffer.decode::<u8>()?;
            const MULTI_BYTE_TAG_MASK: u8 = 0x1F;
            // X.509 certificates only use single-byte tags. Multi-byte tags
            // (low 5 bits all set) would cause us to misparse subsequent bytes.
            if tag & MULTI_BYTE_TAG_MASK == MULTI_BYTE_TAG_MASK {
                return Err(DecoderError::InvariantViolation(
                    "multi-byte tags not supported",
                ));
            }
            let (DerLength(len), buffer) = buffer.decode::<DerLength>()?;
            let (content, buffer) = buffer.decode_slice(len)?;
            Ok((
                Tlv {
                    tag,
                    content: content.into_less_safe_slice(),
                },
                buffer,
            ))
        }
    }

    /// Macro to define a typed DER element that decodes a TLV and asserts the
    /// expected tag. Each generated struct contains only the content bytes.
    macro_rules! der_element {
        ($name:ident, $tag:expr, $doc:expr) => {
            #[doc = $doc]
            pub struct $name<'a> {
                pub content: &'a [u8],
            }

            impl<'a> DecoderValue<'a> for $name<'a> {
                fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
                    let (tlv, buffer) = buffer.decode::<Tlv<'a>>()?;
                    if tlv.tag != $tag {
                        return Err(DecoderError::InvariantViolation(concat!(
                            "expected ",
                            stringify!($name)
                        )));
                    }
                    Ok((
                        $name {
                            content: tlv.content,
                        },
                        buffer,
                    ))
                }
            }
        };
    }

    der_element!(DerSequence, TAG_SEQUENCE, "A DER SEQUENCE element.");
    der_element!(DerSet, TAG_SET, "A DER SET element.");
    der_element!(DerInteger, TAG_INTEGER, "A DER INTEGER element.");
    der_element!(DerOid, TAG_OID, "A DER OID element.");
    der_element!(DerContext0, TAG_CONTEXT_0, "A DER [0] EXPLICIT element.");

    /// A DER BIT STRING element.
    ///
    /// The first content byte is the unused bits count (0–7), indicating how
    /// many trailing bits in the last byte are padding.
    pub struct DerBitString<'a> {
        pub unused_bits: u8,
        pub content: &'a [u8],
    }

    impl<'a> DecoderValue<'a> for DerBitString<'a> {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            let (tlv, buffer) = buffer.decode::<Tlv<'a>>()?;
            if tlv.tag != TAG_BIT_STRING {
                return Err(DecoderError::InvariantViolation("expected DerBitString"));
            }
            let (&unused_bits, content) =
                tlv.content
                    .split_first()
                    .ok_or(DecoderError::InvariantViolation(
                        "BIT STRING content too short",
                    ))?;
            Ok((
                DerBitString {
                    unused_bits,
                    content,
                },
                buffer,
            ))
        }
    }

    /// A DER string element that must contain valid UTF-8.
    ///
    /// Accepts UTF8String (0x0c), PrintableString (0x13), and IA5String (0x16).
    pub struct DerUtf8ishString<'a> {
        pub content: &'a str,
    }

    impl<'a> DecoderValue<'a> for DerUtf8ishString<'a> {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            let (tlv, buffer) = buffer.decode::<Tlv<'a>>()?;
            match tlv.tag {
                // PrintableString and IA5String are subsets of UTF-8
                TAG_UTF8_STRING | TAG_PRINTABLE_STRING | TAG_IA5_STRING => {}
                _ => {
                    return Err(DecoderError::InvariantViolation(
                        "expected UTF-8 string tag",
                    ));
                }
            }
            let content = core::str::from_utf8(tlv.content)
                .map_err(|_| DecoderError::InvariantViolation("invalid utf8"))?;
            Ok((DerUtf8ishString { content }, buffer))
        }
    }

    /// Helper: decode an OID and return the raw content bytes.
    fn decode_oid<'a>(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, &'a [u8]> {
        let (oid, buffer) = buffer.decode::<DerOid<'a>>()?;
        Ok((oid.content, buffer))
    }

    /// The RSA public key decoded from a BIT STRING containing
    /// SEQUENCE { INTEGER(modulus), INTEGER(exponent) }.
    struct RsaPublicKey<'a> {
        modulus: &'a [u8],
    }

    impl<'a> DecoderValue<'a> for RsaPublicKey<'a> {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            // BIT STRING wrapper
            let (bits, buffer) = buffer.decode::<DerBitString<'a>>()?;
            if bits.unused_bits != 0 {
                return Err(DecoderError::InvariantViolation(
                    "BIT STRING has non-zero unused bits",
                ));
            }
            // outer SEQUENCE
            let (seq, _) = DecoderBuffer::new(bits.content).decode::<DerSequence<'_>>()?;
            // first INTEGER is the modulus
            let (modulus_int, _) = DecoderBuffer::new(seq.content).decode::<DerInteger<'_>>()?;
            let modulus = modulus_int.content;
            // strip leading 0x00 sign padding
            let modulus = if modulus.first() == Some(&0x00) {
                modulus.get(1..).unwrap_or(modulus)
            } else {
                modulus
            };
            Ok((RsaPublicKey { modulus }, buffer))
        }
    }

    /// Decode a KeyType from the content of a subjectPublicKeyInfo SEQUENCE.
    impl<'a> DecoderValue<'a> for super::KeyType {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            use super::KeyType;

            // AlgorithmIdentifier SEQUENCE
            let (key_alg, rest) = buffer.decode::<DerSequence<'a>>()?;
            let (key_oid, key_alg_rest) = decode_oid(DecoderBuffer::new(key_alg.content))?;

            match key_oid {
                OID_EC_PUBLIC_KEY => {
                    let (curve_oid, _) = decode_oid(key_alg_rest)?;
                    let key_type = match curve_oid {
                        OID_SECP256R1 => KeyType::Secp256r1,
                        OID_SECP384R1 => KeyType::Secp384r1,
                        OID_SECP521R1 => KeyType::Secp521r1,
                        _ => KeyType::Unknown,
                    };
                    Ok((key_type, rest))
                }
                OID_RSA_KEY | OID_RSA_PSS_KEY => {
                    let (rsa_key, buffer) = rest.decode::<RsaPublicKey<'_>>()?;
                    let is_pss = key_oid == OID_RSA_PSS_KEY;

                    let key_type = match (is_pss, rsa_key.modulus.len() * 8) {
                        (false, 1024) => KeyType::Rsa1024,
                        (false, 2048) => KeyType::Rsa2048,
                        (false, 3072) => KeyType::Rsa3072,
                        (false, 4096) => KeyType::Rsa4096,
                        (true, 2048) => KeyType::RsaPss2048,
                        (true, 3072) => KeyType::RsaPss3072,
                        (true, 4096) => KeyType::RsaPss4096,
                        _ => KeyType::Unknown,
                    };
                    Ok((key_type, buffer))
                }
                _ => Ok((KeyType::Unknown, rest)),
            }
        }
    }

    /// Extract the Common Name (CN) from a Relative Distinguished Name (RDN) Sequence.
    ///
    /// For our purposes, we discard all other fields (e.g. organization, country)
    ///
    /// Returns an empty string if no CN is found.
    fn decode_common_name(content: &[u8]) -> Result<String, DecoderError> {
        let mut buffer = DecoderBuffer::new(content);
        while !buffer.is_empty() {
            let (set, rest) = buffer.decode::<DerSet<'_>>()?;
            let mut set_buf = DecoderBuffer::new(set.content);
            while !set_buf.is_empty() {
                let (attr, set_rest) = set_buf.decode::<DerSequence<'_>>()?;
                let (oid, val_buf) = DecoderBuffer::new(attr.content).decode::<DerOid<'_>>()?;
                if oid.content == OID_CN {
                    let (cn, _) = val_buf.decode::<DerUtf8ishString<'_>>()?;
                    return Ok(cn.content.to_string());
                }
                set_buf = set_rest;
            }
            buffer = rest;
        }
        Ok(String::new())
    }

    impl<'a> DecoderValue<'a> for super::ParsedCertContent {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            // Certificate ::= SEQUENCE { tbs, sigAlg, sig }
            let (cert_seq, _buffer) = buffer.decode::<DerSequence<'a>>()?;

            // TBSCertificate ::= SEQUENCE { ... }
            let (tbs, _) = DecoderBuffer::new(cert_seq.content).decode::<DerSequence<'a>>()?;
            let mut buffer = DecoderBuffer::new(tbs.content);

            // [0] EXPLICIT version (optional, tag 0xa0)
            if buffer.peek_byte(0)? == TAG_CONTEXT_0 {
                let (_, b) = buffer.decode::<DerContext0<'a>>()?;
                buffer = b;
            }

            // serial
            let (serial, buffer) = buffer.decode::<DerInteger<'a>>()?;

            // signature AlgorithmIdentifier
            let (sig_alg, buffer) = buffer.decode::<DerSequence<'a>>()?;
            let (sig_oid, _) = decode_oid(DecoderBuffer::new(sig_alg.content))?;

            // issuer
            let (issuer, buffer) = buffer.decode::<DerSequence<'a>>()?;

            // validity (skip)
            let (_, buffer) = buffer.decode::<DerSequence<'a>>()?;

            // subject
            let (subject, buffer) = buffer.decode::<DerSequence<'a>>()?;

            // subjectPublicKeyInfo
            let (spki, _) = buffer.decode::<DerSequence<'a>>()?;
            let (key_type, _) = DecoderBuffer::new(spki.content).decode::<super::KeyType>()?;

            Ok((
                super::ParsedCertContent {
                    serial: serial.content.to_vec(),
                    issuer: decode_common_name(issuer.content)?,
                    common_name: decode_common_name(subject.content)?,
                    key_type,
                    signature: super::SignatureAlgorithm::from_oid(sig_oid),
                },
                DecoderBuffer::new(&[]),
            ))
        }
    }
}

/// Parse a DER-encoded certificate into its component fields.
pub fn parse(der: &[u8]) -> Result<ParsedCertContent, DecoderError> {
    let buf = s2n_codec::DecoderBuffer::new(der);
    let (parsed, _) = buf.decode::<ParsedCertContent>()?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use s2n_tls::testing::{CertKeyPair, TestPair};

    /// Helper: do a handshake with the given cert and return the leaf DER.
    fn handshake_leaf_der(prefix: &str) -> Vec<u8> {
        let cert = CertKeyPair::from_path(prefix, "cert", "key", "cert");
        let policy = s2n_tls::security::DEFAULT_TLS13;
        let mut builder = s2n_tls::config::Builder::new();
        builder.set_security_policy(&policy).unwrap();
        builder.load_pem(cert.cert(), cert.key()).unwrap();
        builder.trust_pem(cert.cert()).unwrap();
        builder
            .set_verify_host_callback(s2n_tls::testing::InsecureAcceptAllCertificatesHandler {})
            .unwrap();
        builder.with_system_certs(false).unwrap();
        let config = builder.build().unwrap();
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();
        let chain = pair.server.selected_cert().unwrap();
        chain
            .iter()
            .next()
            .unwrap()
            .unwrap()
            .der()
            .unwrap()
            .to_vec()
    }

    const S2N_LOCALHOST: &str = "localhost";

    /// All s2n-tls test certs are self-signed CN=localhost certs that differ
    /// only in key type, signature algorithm, and serial number.
    #[test]
    fn s2n_test_certs() {
        let cases: &[(&str, &[u8], KeyType, SignatureAlgorithm)] = &[
            (
                "rsa_2048_sha256_client_",
                &[0x00, 0xa9, 0xea, 0x92, 0x92, 0x5c, 0x65, 0x56, 0x34],
                KeyType::Rsa2048,
                SignatureAlgorithm::RsaPkcsSha256,
            ),
            (
                "rsa_2048_sha384_client_",
                &[0x00, 0xf5, 0x20, 0xe0, 0xfd, 0x51, 0xdd, 0xcb, 0x40],
                KeyType::Rsa2048,
                SignatureAlgorithm::RsaPkcsSha384,
            ),
            (
                "rsa_4096_sha512_client_",
                &[0x00, 0xda, 0x54, 0x50, 0xbd, 0xeb, 0x60, 0xcb, 0x7d],
                KeyType::Rsa4096,
                SignatureAlgorithm::RsaPkcsSha512,
            ),
            (
                "ecdsa_p256_pkcs1_",
                &[
                    0x3d, 0x86, 0x04, 0x9c, 0xad, 0xb8, 0xa8, 0x3c, 0xf3, 0xe7, 0xd2, 0x08, 0x0d,
                    0xc3, 0x4b, 0x73, 0x83, 0xf6, 0x1f, 0x9b,
                ],
                KeyType::Secp256r1,
                SignatureAlgorithm::EcdsaSha256,
            ),
            (
                "ecdsa_p384_pkcs1_",
                &[
                    0x33, 0x15, 0x1a, 0x7b, 0xe6, 0xb3, 0x75, 0xad, 0x4c, 0x49, 0x9d, 0xde, 0xb1,
                    0xc2, 0x5f, 0x25, 0x36, 0x70, 0x45, 0xa9,
                ],
                KeyType::Secp384r1,
                SignatureAlgorithm::EcdsaSha256,
            ),
            (
                "localhost_rsa_pss_2048_sha256_",
                &[
                    0x31, 0x94, 0xe2, 0x4a, 0xc2, 0x96, 0xdc, 0xe9, 0x94, 0x3d, 0xfd, 0x67, 0xc4,
                    0xa8, 0x94, 0x52, 0x05, 0xc2, 0x77, 0x44,
                ],
                KeyType::RsaPss2048,
                SignatureAlgorithm::RsaPss,
            ),
        ];

        for (prefix, serial, key_type, signature) in cases {
            let der = handshake_leaf_der(prefix);
            let expected = ParsedCertContent {
                serial: serial.to_vec(),
                issuer: S2N_LOCALHOST.into(),
                common_name: S2N_LOCALHOST.into(),
                key_type: key_type.clone(),
                signature: signature.clone(),
            };
            assert_eq!(parse(&der).unwrap(), expected, "failed for {prefix}");
        }
    }

    /// This tests are cert parsing against the public certificate chain returned by
    /// `sqs.us-east-2.amazonaws.com`
    #[test]
    fn sqs_cert_chain() {
        const SQS_LEAF: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/test_certs/sqs_leaf.der"
        ));
        const SQS_INTERMEDIATE: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/test_certs/sqs_intermediate.der"
        ));
        const SQS_ROOT: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/test_certs/sqs_root.der"
        ));

        assert_eq!(
            parse(SQS_LEAF).unwrap(),
            ParsedCertContent {
                serial: vec![
                    0x06, 0xb1, 0xde, 0xc6, 0x59, 0x3a, 0x5f, 0x5d, 0x52, 0xcc, 0xce, 0x05, 0x13,
                    0x23, 0x8d, 0x1c,
                ],
                issuer: "Amazon RSA 2048 M04".into(),
                common_name: "sqs.us-east-2.amazonaws.com".into(),
                key_type: KeyType::Rsa2048,
                signature: SignatureAlgorithm::RsaPkcsSha256,
            }
        );

        assert_eq!(
            parse(SQS_INTERMEDIATE).unwrap(),
            ParsedCertContent {
                serial: vec![
                    0x07, 0x73, 0x12, 0x4f, 0x2a, 0x95, 0x2e, 0x3e, 0xd1, 0x8a, 0x58, 0xbd, 0xb8,
                    0x5d, 0x1b, 0xc0, 0xce, 0x5f, 0x27,
                ],
                issuer: "Amazon Root CA 1".into(),
                common_name: "Amazon RSA 2048 M04".into(),
                key_type: KeyType::Rsa2048,
                signature: SignatureAlgorithm::RsaPkcsSha256,
            }
        );

        assert_eq!(
            parse(SQS_ROOT).unwrap(),
            ParsedCertContent {
                serial: vec![
                    0x06, 0x7f, 0x94, 0x4a, 0x2a, 0x27, 0xcd, 0xf3, 0xfa, 0xc2, 0xae, 0x2b, 0x01,
                    0xf9, 0x08, 0xee, 0xb9, 0xc4, 0xc6,
                ],
                issuer: "Starfield Services Root Certificate Authority - G2".into(),
                common_name: "Amazon Root CA 1".into(),
                key_type: KeyType::Rsa2048,
                signature: SignatureAlgorithm::RsaPkcsSha256,
            }
        );
    }

    /// We should gracefully parse certs with unknown cert types, returning the
    /// well-defined "unknown" enums.
    ///
    /// Internally, this is an Ed25519 cert produced with OpenSSL. s2n-tls doesn't
    /// support Ed25519, which is why we don't actually support this value.
    #[test]
    fn ed25519_unknown_key_type() {
        assert_eq!(
            parse(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/resources/test_certs/ed25519_cert.der"
            )))
            .unwrap(),
            ParsedCertContent {
                serial: vec![
                    0x5b, 0x9d, 0xf7, 0x74, 0x5d, 0x46, 0x4e, 0xaf, 0x5f, 0x71, 0x9a, 0xb9, 0xa1,
                    0xb9, 0x55, 0xf9, 0xfe, 0x8b, 0x71, 0x59,
                ],
                issuer: "localhost".into(),
                common_name: "localhost".into(),
                key_type: KeyType::Unknown,
                signature: SignatureAlgorithm::Unknown,
            }
        );
    }

    #[test]
    fn error_cases() {
        // garbage data
        assert!(parse(&[0xff, 0x00]).is_err());

        // empty data
        assert!(parse(&[]).is_err());

        // truncated data
        let der = handshake_leaf_der("rsa_2048_sha256_client_");
        assert!(parse(&der[..der.len() / 2]).is_err());
    }
}
