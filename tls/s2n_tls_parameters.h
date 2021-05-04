/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#pragma once

#include "crypto/s2n_hash.h"

/* Codes from http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5 */
#define TLS_NULL_WITH_NULL_NULL             0x00, 0x00
#define TLS_RSA_WITH_AES_256_CBC_SHA256     0x00, 0x3D
#define TLS_RSA_WITH_AES_256_CBC_SHA        0x00, 0x35
#define TLS_RSA_WITH_AES_128_CBC_SHA256     0x00, 0x3C
#define TLS_RSA_WITH_AES_128_CBC_SHA        0x00, 0x2F
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA       0x00, 0x0A
#define TLS_RSA_WITH_RC4_128_MD5            0x00, 0x04
#define TLS_RSA_WITH_RC4_128_SHA            0x00, 0x05

#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA    0x00, 0x33
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 0x00, 0x67
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA    0x00, 0x39
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 0x00, 0x6B
#define TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA   0x00, 0x16

#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA       0xC0, 0x09
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256    0xC0, 0x23
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA       0xC0, 0x0A
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384    0xC0, 0x24

#define TLS_ECDHE_RSA_WITH_RC4_128_SHA           0xC0, 0x11
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA       0xC0, 0x13
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256    0xC0, 0x27
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA       0xC0, 0x14
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384    0xC0, 0x28
#define TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA      0xC0, 0x12

#define TLS_RSA_WITH_AES_128_GCM_SHA256          0x00, 0x9C
#define TLS_RSA_WITH_AES_256_GCM_SHA384          0x00, 0x9D
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256      0x00, 0x9E
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384      0x00, 0x9F
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  0xC0, 0x2B
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  0xC0, 0x2C
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    0xC0, 0x2F
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384    0xC0, 0x30

#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256    0xCC, 0xA8
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256  0xCC, 0xA9
#define TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256      0xCC, 0xAA

/* TLS 1.2 hybrid post-quantum definitions from https://tools.ietf.org/html/draft-campagna-tls-bike-sike-hybrid */
#define TLS_ECDHE_BIKE_RSA_WITH_AES_256_GCM_SHA384 0xFF, 0x04
#define TLS_ECDHE_SIKE_RSA_WITH_AES_256_GCM_SHA384 0xFF, 0x08
#define TLS_ECDHE_KYBER_RSA_WITH_AES_256_GCM_SHA384 0xFF, 0x0C
#define TLS_EXTENSION_PQ_KEM_PARAMETERS 0xFE01
#define TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R1 1
#define TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R2 13
#define TLS_PQ_KEM_EXTENSION_ID_BIKE1_L1_R3 25
#define TLS_PQ_KEM_EXTENSION_ID_SIKE_P503_R1 10
#define TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R2 19
#define TLS_PQ_KEM_EXTENSION_ID_SIKE_P434_R3 19 /* Not a typo; sikep434 r2 and r3 use the same extension ID */
#define TLS_PQ_KEM_EXTENSION_ID_KYBER_512_R2 23
#define TLS_PQ_KEM_EXTENSION_ID_KYBER_512_90S_R2 24
#define TLS_PQ_KEM_EXTENSION_ID_KYBER_512_R3 28

/* TLS 1.3 hybrid post-quantum definitions are from the proposed reserved range defined
 * in https://tools.ietf.org/html/draft-stebila-tls-hybrid-design. Values for interoperability
 * are defined in https://docs.google.com/spreadsheets/d/12YarzaNv3XQNLnvDsWLlRKwtZFhRrDdWf36YlzwrPeg/edit#gid=0. */
#define TLS_PQ_KEM_GROUP_ID_X25519_SIKE_P434_R2 0x2F27
#define TLS_PQ_KEM_GROUP_ID_SECP256R1_SIKE_P434_R2 0x2F1F
#define TLS_PQ_KEM_GROUP_ID_X25519_BIKE1_L1_R2 0x2F28
#define TLS_PQ_KEM_GROUP_ID_SECP256R1_BIKE1_L1_R2 0x2F23
#define TLS_PQ_KEM_GROUP_ID_X25519_KYBER_512_R2 0x2F26
#define TLS_PQ_KEM_GROUP_ID_SECP256R1_KYBER_512_R2 0x2F0F

/* From https://tools.ietf.org/html/rfc7507 */
#define TLS_FALLBACK_SCSV                   0x56, 0x00
#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV   0x00, 0xff

/* TLS 1.3 cipher suites from https://tools.ietf.org/html/rfc8446#appendix-B.4 */
#define TLS_AES_128_GCM_SHA256              0x13, 0x01
#define TLS_AES_256_GCM_SHA384              0x13, 0x02
#define TLS_CHACHA20_POLY1305_SHA256        0x13, 0x03
#define TLS_AES_128_CCM_SHA256              0x13, 0x04
#define TLS_AES_128_CCM_8_SHA256            0x13, 0x05

/* TLS extensions from https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml */
#define TLS_EXTENSION_SERVER_NAME           0
#define TLS_EXTENSION_MAX_FRAG_LEN          1
#define TLS_EXTENSION_STATUS_REQUEST        5
#define TLS_EXTENSION_SUPPORTED_GROUPS     10
#define TLS_EXTENSION_EC_POINT_FORMATS     11
#define TLS_EXTENSION_SIGNATURE_ALGORITHMS 13
#define TLS_EXTENSION_ALPN                 16
#define TLS_EXTENSION_SCT_LIST             18
#define TLS_EXTENSION_SESSION_TICKET       35
#define TLS_EXTENSION_PRE_SHARED_KEY       41
#define TLS_EXTENSION_CERT_AUTHORITIES     47
#define TLS_EXTENSION_RENEGOTIATION_INFO   65281

/* TLS 1.3 extensions from https://tools.ietf.org/html/rfc8446#section-4.2 */
#define TLS_EXTENSION_EARLY_DATA             42
#define TLS_EXTENSION_SUPPORTED_VERSIONS     43
#define TLS_EXTENSION_COOKIE                 44
#define TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES 45
#define TLS_EXTENSION_KEY_SHARE              51

/* TLS 1.3 pre-shared key exchange modes from https://tools.ietf.org/html/rfc8446#section-4.2.9 */
#define TLS_PSK_KE_MODE     0
#define TLS_PSK_DHE_KE_MODE 1

/**
 *= https://tools.ietf.org/id/draft-ietf-quic-tls-32.txt#8.2
 *#   enum {
 *#      quic_transport_parameters(0xffa5), (65535)
 *#   } ExtensionType;
 */
#define TLS_QUIC_TRANSPORT_PARAMETERS      0xffa5

/* TLS Signature Algorithms - RFC 5246 7.4.1.4.1 */
/* https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16 */
#define TLS_SIGNATURE_ALGORITHM_ANONYMOUS   0
#define TLS_SIGNATURE_ALGORITHM_RSA         1
#define TLS_SIGNATURE_ALGORITHM_DSA         2
#define TLS_SIGNATURE_ALGORITHM_ECDSA       3
#define TLS_SIGNATURE_ALGORITHM_PRIVATE     224

#define TLS_SIGNATURE_ALGORITHM_COUNT       4

/* TLS Hash Algorithm - https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1 */
/* https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18 */
#define TLS_HASH_ALGORITHM_ANONYMOUS        0
#define TLS_HASH_ALGORITHM_MD5              1
#define TLS_HASH_ALGORITHM_SHA1             2
#define TLS_HASH_ALGORITHM_SHA224           3
#define TLS_HASH_ALGORITHM_SHA256           4
#define TLS_HASH_ALGORITHM_SHA384           5
#define TLS_HASH_ALGORITHM_SHA512           6
#define TLS_HASH_ALGORITHM_COUNT            7

/* TLS SignatureScheme (Backwards compatible with SigHash and SigAlg values above) */
/* Defined here: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme */
#define TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA1             0x0201
#define TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA224           0x0301
#define TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA256           0x0401
#define TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA384           0x0501
#define TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA512           0x0601

/* In TLS 1.0 and 1.1 the hard-coded default scheme was RSA_PKCS1_MD5_SHA1, but there's no IANA defined backwards
 * compatible value for that Scheme for TLS 1.2 and 1.3. So we define an internal value in the private range that won't
 * match anything in the valid range so that all TLS Versions can use the same SignatureScheme negotiation abstraction
 * layer. This scheme isn't in any preference list, so it can't be negotiated even if a client sent it in its pref list. */
#define TLS_SIGNATURE_SCHEME_PRIVATE_INTERNAL_RSA_PKCS1_MD5_SHA1         0xFFFF

/* TLS 1.2 Backwards Compatible ECDSA Schemes */
#define TLS_SIGNATURE_SCHEME_ECDSA_SHA1                 0x0203
#define TLS_SIGNATURE_SCHEME_ECDSA_SHA224               0x0303
#define TLS_SIGNATURE_SCHEME_ECDSA_SHA256               0x0403
#define TLS_SIGNATURE_SCHEME_ECDSA_SHA384               0x0503
#define TLS_SIGNATURE_SCHEME_ECDSA_SHA512               0x0603

/* TLS 1.3 ECDSA Signature Schemes */
#define TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256     0x0403
#define TLS_SIGNATURE_SCHEME_ECDSA_SECP384R1_SHA384     0x0503
#define TLS_SIGNATURE_SCHEME_ECDSA_SECP521R1_SHA512     0x0603
#define TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256        0x0804
#define TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384        0x0805
#define TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512        0x0806
#define TLS_SIGNATURE_SCHEME_ED25519                    0x0807
#define TLS_SIGNATURE_SCHEME_ED448                      0x0808
#define TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA256         0x0809
#define TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA384         0x080A
#define TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA512         0x080B


#define TLS_SIGNATURE_SCHEME_LEN                        2
#define TLS_SIGNATURE_SCHEME_LIST_MAX_LEN               64

/* The TLS record types we support */
#define SSLv2_CLIENT_HELLO     1
#define TLS_CHANGE_CIPHER_SPEC 20
#define TLS_ALERT              21
#define TLS_HANDSHAKE          22
#define TLS_APPLICATION_DATA   23

/* Elliptic curve formats from http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-9
 * Only uncompressed is supported.
 */
#define TLS_EC_FORMAT_UNCOMPRESSED               0
#define TLS_EC_FORMAT_ANSIX962_COMPRESSED_PRIME  1
#define TLS_EC_FORMAT_ANSIX962_COMPRESSED_CHAR2  2

/* Elliptic curves from https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8 */
#define TLS_EC_CURVE_SECP_256_R1           23
#define TLS_EC_CURVE_SECP_384_R1           24
#define TLS_EC_CURVE_SECP_521_R1           25
#define TLS_EC_CURVE_ECDH_X25519           29
#define TLS_EC_CURVE_ECDH_X448             30

/* Ethernet maximum transmission unit (MTU)
 * MTU is usually associated with the Ethernet protocol,
 * where a 1500-byte packet is the largest allowed in it
 */
#define ETH_MTU 1500

#define IP_V4_HEADER_LENGTH 20
#define IP_V6_HEADER_LENGTH 40

#define TCP_HEADER_LENGTH 20
#define TCP_OPTIONS_LENGTH 40

/* The maximum size of a TLS record is 16389 bytes. This is;  1 byte for content
 * type, 2 bytes for the protocol version, 2 bytes for the length field,
 * and then up to 2^14 for the encrypted+compressed payload data.
 */
#define S2N_TLS_RECORD_HEADER_LENGTH    5
#define S2N_TLS_MAXIMUM_FRAGMENT_LENGTH 16384
/* Maximum TLS record length allows for 2048 octets of compression expansion and padding */
#define S2N_TLS_MAXIMUM_RECORD_LENGTH   (S2N_TLS_MAXIMUM_FRAGMENT_LENGTH + S2N_TLS_RECORD_HEADER_LENGTH + 2048)
#define S2N_TLS_MAX_FRAG_LEN_EXT_NONE   0

/* TLS1.3 has a max fragment length of 2^14 + 1 byte for the content type */
#define S2N_TLS13_MAXIMUM_FRAGMENT_LENGTH 16385
/* Max encryption overhead is 255 for AEAD padding */
#define S2N_TLS13_MAXIMUM_RECORD_LENGTH   (S2N_TLS13_MAXIMUM_FRAGMENT_LENGTH + S2N_TLS_RECORD_HEADER_LENGTH + 255)

/* The maximum size of an SSL2 message is 2^14 - 1, as neither of the first two
 * bits in the length field are usable. Per;
 * http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html
 * section 1.1
 */
#define S2N_SSL2_RECORD_HEADER_LENGTH   2
#define S2N_SSL2_MAXIMUM_MESSAGE_LENGTH 16383
#define S2N_SSL2_MAXIMUM_RECORD_LENGTH  (S2N_SSL2_MAXIMUM_MESSAGE_LENGTH + S2N_SSL2_RECORD_HEADER_LENGTH)

/* s2n can use a "small" record length that is aligned to the dominant internet MTU;
 * 1500 bytes, minus 20 bytes for an IP header, minus 20 bytes for a tcp
 * header and 20 bytes for tcp/ip options (timestamp, sack etc) and a "large" record
 * length that is designed to maximize throughput (fewer MACs per byte transferred
 * and better efficiency of crypto engines).
 */
#define S2N_SMALL_RECORD_LENGTH (1500 - 20 - 20 - 20)
#define S2N_SMALL_FRAGMENT_LENGTH (S2N_SMALL_RECORD_LENGTH - S2N_TLS_RECORD_HEADER_LENGTH)

/* Testing in the wild has found 8k max record sizes give a good balance of low latency
 * and throughput.
 */
#define S2N_DEFAULT_RECORD_LENGTH 8092
#define S2N_DEFAULT_FRAGMENT_LENGTH (S2N_DEFAULT_RECORD_LENGTH - S2N_TLS_RECORD_HEADER_LENGTH)

/* S2N_LARGE_RECORD_LENGTH is used for initializing output buffers, we use the largest
 * possible value of all supported protocols to avoid branching at runtime
 */
#define S2N_LARGE_RECORD_LENGTH S2N_TLS_MAXIMUM_RECORD_LENGTH
#define S2N_LARGE_FRAGMENT_LENGTH S2N_TLS_MAXIMUM_FRAGMENT_LENGTH
#define S2N_TLS13_LARGE_FRAGMENT_LENGTH S2N_TLS13_MAXIMUM_FRAGMENT_LENGTH

/* Cap dynamic record resize threshold to 8M */
#define S2N_TLS_MAX_RESIZE_THRESHOLD (1024 * 1024 * 8)

/* Put a 64k cap on the size of any handshake message */
#define S2N_MAXIMUM_HANDSHAKE_MESSAGE_LENGTH (64 * 1024)

/* Maximum size for full encoded TLSInnerPlaintext (https://tools.ietf.org/html/rfc8446#section-5.4) */
#define S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH ((1 << 14) + 1)

/* Alert messages are always 2 bytes long */
#define S2N_ALERT_LENGTH 2

/* Handshake messages have their own header too */
#define TLS_HANDSHAKE_HEADER_LENGTH   4

#define S2N_MAX_SERVER_NAME 255
