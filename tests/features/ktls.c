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

/*
 * https://github.com/aws/s2n-tls/issues/3813
 *
 * _GNU_SOURCE is needed for resolving the constant SOL_TCP
 * when building `tls/s2n_ktls.c`.
 */
#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
    #include <netinet/tcp.h>
    #undef _GNU_SOURCE
#else
    #include <netinet/tcp.h>
#endif

#include <linux/tls.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define S2N_TLS_ULP_NAME      "tls"
#define S2N_TLS_ULP_NAME_SIZE sizeof(S2N_TLS_ULP_NAME)

int main()
{
    /* Prepare dummy crypto info for socket */
    uint8_t implicit_iv[16] = { 0 };
    uint8_t sequence_number[8] = { 0 };
    uint8_t key[16] = { 0 };
    struct tls12_crypto_info_aes_gcm_128 crypto_info;
    crypto_info.info.version = TLS_1_2_VERSION;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
    memcpy(crypto_info.iv, implicit_iv, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memcpy(crypto_info.rec_seq, sequence_number,
            TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    memcpy(crypto_info.key, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(crypto_info.salt, implicit_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

    /* Attempt to enable kTLS */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(sock, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
    setsockopt(sock, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));

    return 0;
}
