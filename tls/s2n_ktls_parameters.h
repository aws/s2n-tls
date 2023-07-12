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

/*
 * Linux doesn't expose kTLS headers in its uapi. Its possible to get these headers
 * via glibc but support can vary depending on the version of glibc on the host.
 * Instead we define linux specific values inline.
 *
 * - https://elixir.bootlin.com/linux/v6.3.8/A/ident/TCP_ULP
 * - https://elixir.bootlin.com/linux/v6.3.8/A/ident/SOL_TCP
 */

#if defined(__linux__)
    #define S2N_KTLS_SUPPORTED true

    /* socket definitions */
    #define S2N_TCP_ULP 31 /* Attach a ULP to a TCP connection.  */
    #define S2N_SOL_TCP 6  /* TCP level */
    #define S2N_SOL_TLS 282
    #define S2N_TLS_TX  1 /* Set transmit parameters */
    #define S2N_TLS_RX  2 /* Set receive parameters */

    /* cipher definitions */
    #define S2N_TLS_CIPHER_AES_GCM_128              51
    #define S2N_TLS_CIPHER_AES_GCM_128_IV_SIZE      8
    #define S2N_TLS_CIPHER_AES_GCM_128_KEY_SIZE     16
    #define S2N_TLS_CIPHER_AES_GCM_128_SALT_SIZE    4
    #define S2N_TLS_CIPHER_AES_GCM_128_TAG_SIZE     16
    #define S2N_TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE 8

#else
    /* For unsupported platforms 0-init (array of size 1) all values. */
    #define S2N_KTLS_SUPPORTED                      false

    /* socket definitions */
    #define S2N_TCP_ULP                             0
    #define S2N_SOL_TCP                             0
    #define S2N_SOL_TLS                             0
    #define S2N_TLS_TX                              0
    #define S2N_TLS_RX                              0

    /* cipher definitions */
    #define S2N_TLS_CIPHER_AES_GCM_128              0
    #define S2N_TLS_CIPHER_AES_GCM_128_IV_SIZE      1
    #define S2N_TLS_CIPHER_AES_GCM_128_KEY_SIZE     1
    #define S2N_TLS_CIPHER_AES_GCM_128_SALT_SIZE    1
    #define S2N_TLS_CIPHER_AES_GCM_128_TAG_SIZE     1
    #define S2N_TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE 1

#endif

/* Common */
#define S2N_TLS_ULP_NAME      "tls"
#define S2N_TLS_ULP_NAME_SIZE sizeof(S2N_TLS_ULP_NAME)

typedef unsigned short __u16;

struct s2n_tls_crypto_info {
    __u16 version;
    __u16 cipher_type;
};

struct s2n_tls12_crypto_info_aes_gcm_128 {
    struct s2n_tls_crypto_info info;
    unsigned char iv[S2N_TLS_CIPHER_AES_GCM_128_IV_SIZE];
    unsigned char key[S2N_TLS_CIPHER_AES_GCM_128_KEY_SIZE];
    unsigned char salt[S2N_TLS_CIPHER_AES_GCM_128_SALT_SIZE];
    unsigned char rec_seq[S2N_TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

/* tls definitions */
#define S2N_TLS_VERSION_NUMBER(id) ((((id##_VERSION_MAJOR) & 0xFF) << 8) | ((id##_VERSION_MINOR) & 0xFF))
#define S2N_TLS_1_2_VERSION_MAJOR  0x3
#define S2N_TLS_1_2_VERSION_MINOR  0x3
#define S2N_TLS_1_2_VERSION        S2N_TLS_VERSION_NUMBER(S2N_TLS_1_2)
