/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256  0xCC, 0xA8
#define TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256    0xCC, 0xAA

/* From https://tools.ietf.org/html/rfc7507 */
#define TLS_FALLBACK_SCSV                   0x56, 0x00
#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV   0x00, 0xff

/* TLS extensions from https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml */
#define TLS_EXTENSION_SERVER_NAME           0
#define TLS_EXTENSION_MAX_FRAG_LEN          1
#define TLS_EXTENSION_STATUS_REQUEST        5
#define TLS_EXTENSION_ELLIPTIC_CURVES      10
#define TLS_EXTENSION_EC_POINT_FORMATS     11
#define TLS_EXTENSION_SIGNATURE_ALGORITHMS 13
#define TLS_EXTENSION_ALPN                 16
#define TLS_EXTENSION_SCT_LIST             18
#define TLS_EXTENSION_RENEGOTIATION_INFO   65281
#define TLS_EXTENSION_SESSION_TICKET       35

/* TLS Signature Algorithms - RFC 5246 7.4.1.4.1*/
#define TLS_SIGNATURE_ALGORITHM_ANONYMOUS   0
#define TLS_SIGNATURE_ALGORITHM_RSA         1
#define TLS_SIGNATURE_ALGORITHM_DSA         2
#define TLS_SIGNATURE_ALGORITHM_ECDSA       3

#define TLS_SIGNATURE_ALGORITHM_COUNT       4

#define TLS_HASH_ALGORITHM_ANONYMOUS        0
#define TLS_HASH_ALGORITHM_MD5              1
#define TLS_HASH_ALGORITHM_SHA1             2
#define TLS_HASH_ALGORITHM_SHA224           3
#define TLS_HASH_ALGORITHM_SHA256           4
#define TLS_HASH_ALGORITHM_SHA384           5
#define TLS_HASH_ALGORITHM_SHA512           6

#define TLS_HASH_ALGORITHM_COUNT            7

/* The TLS record types we support */
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
#define S2N_TLS_MAXIMUM_RECORD_LENGTH   (S2N_TLS_MAXIMUM_FRAGMENT_LENGTH + S2N_TLS_RECORD_HEADER_LENGTH)
#define S2N_TLS_MAX_FRAG_LEN_EXT_NONE   0

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

#define S2N_LARGE_RECORD_LENGTH S2N_TLS_MAXIMUM_RECORD_LENGTH
#define S2N_LARGE_FRAGMENT_LENGTH S2N_TLS_MAXIMUM_FRAGMENT_LENGTH

/* Cap dynamic record resize threshold to 8M */
#define S2N_TLS_MAX_RESIZE_THRESHOLD (1024 * 1024 * 8)

/* Put a 64k cap on the size of any handshake message */
#define S2N_MAXIMUM_HANDSHAKE_MESSAGE_LENGTH (64 * 1024)

/* Alert messages are always 2 bytes long */
#define S2N_ALERT_LENGTH 2

/* Handshake messages have their own header too */
#define TLS_HANDSHAKE_HEADER_LENGTH   4
