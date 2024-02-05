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

/* Needed to set up X25519 key shares */
#include <openssl/evp.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls13_key_schedule.h"
#include "tls/s2n_tls13_secrets.h"

struct s2n_cipher_suite *cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
const struct s2n_ecc_named_curve *curve = &s2n_ecc_curve_x25519;

const uint32_t test_handshake_type = NEGOTIATED | FULL_HANDSHAKE;
const int server_hello_message_num = 1;

const s2n_mode modes[] = { S2N_CLIENT, S2N_SERVER };

S2N_RESULT s2n_extract_early_secret(struct s2n_psk *psk);
S2N_RESULT s2n_tls13_extract_secret(struct s2n_connection *conn, s2n_extract_secret_type_t secret_type);
S2N_RESULT s2n_tls13_derive_secret(struct s2n_connection *conn, s2n_extract_secret_type_t secret_type,
        s2n_mode mode, struct s2n_blob *secret);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_blob derived_secret = { 0 };
    uint8_t derived_secret_bytes[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&derived_secret,
            derived_secret_bytes, S2N_TLS13_SECRET_MAX_LEN));

    /*
     * Simple 1-RTT Handshake
     */
    {
        /**
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
         *= type=test
         *#    {client}  extract secret "early" (same as server early secret)
         *
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
         *= type=test
         *#    {server}  extract secret "early":
         *#
         *#       salt:  0 (all zero octets)
         *#
         *#       IKM (32 octets):  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#          00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#
         *#       secret (32 octets):  33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c
         *#          e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a
         */
        S2N_BLOB_FROM_HEX(early_secret, "33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c \
               e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a");

        /* Extract EARLY_SECRET */
        {
            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;

                EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_EARLY_SECRET));
                EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.extract_secret,
                        early_secret.data, early_secret.size);
                EXPECT_EQUAL(conn->secrets.extract_secret_type, S2N_EARLY_SECRET);
            }
        };

        /**
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
         *= type=test
         *#    {client}  extract secret "handshake" (same as server handshake
         *# secret)
         *
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
         *= type=test
         *#    {server}  extract secret "handshake":
         *#
         *#       salt (32 octets):  6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97
         *#          16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba
         *#
         *#       IKM (32 octets):  8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
         *#          35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d
         *#
         *#       secret (32 octets):  1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b
         *#          01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac
         */
        S2N_BLOB_FROM_HEX(handshake_secret, "1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b \
               01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac");

        /* Extract HANDSHAKE_SECRET
         *
         * The RFC values use x25519, which is only supported via EVP APIs.
         * Additionally, the specific APIs we use to set the EVP key require Openssl-1.1.1.
         */
#if EVP_APIS_SUPPORTED && S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 1)
        {
            const int openssl_type = EVP_PKEY_X25519;

            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {client}  create an ephemeral x25519 key pair:
             *#
             *#       private key (32 octets):  49 af 42 ba 7f 79 94 85 2d 71 3e f2 78
             *#          4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05
             *#
             *#       public key (32 octets):  99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d
             *#          ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c
             */
            S2N_BLOB_FROM_HEX(client_priv, "49 af 42 ba 7f 79 94 85 2d 71 3e f2 78 \
                   4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05");
            S2N_BLOB_FROM_HEX(client_pub, "99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d \
                   ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c");

            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {server}  create an ephemeral x25519 key pair:
             *#
             *#       private key (32 octets):  b1 58 0e ea df 6d d5 89 b8 ef 4f 2d 56
             *#          52 57 8c c8 10 e9 98 01 91 ec 8d 05 83 08 ce a2 16 a2 1e
             *#
             *#       public key (32 octets):  c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6
             *#          72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f
             */
            S2N_BLOB_FROM_HEX(server_priv, "b1 58 0e ea df 6d d5 89 b8 ef 4f 2d 56 \
                      52 57 8c c8 10 e9 98 01 91 ec 8d 05 83 08 ce a2 16 a2 1e");
            S2N_BLOB_FROM_HEX(server_pub, "c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 \
                      72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f");

            /* Server */
            {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;
                EXPECT_OK(s2n_connection_set_test_early_secret(conn, &early_secret));

                conn->kex_params.server_ecc_evp_params.negotiated_curve = curve;
                conn->kex_params.server_ecc_evp_params.evp_pkey = EVP_PKEY_new_raw_private_key(
                        openssl_type, NULL, (unsigned char *) server_priv.data, server_priv.size);
                EXPECT_NOT_NULL(conn->kex_params.server_ecc_evp_params.evp_pkey);

                conn->kex_params.client_ecc_evp_params.negotiated_curve = curve;
                conn->kex_params.client_ecc_evp_params.evp_pkey = EVP_PKEY_new_raw_public_key(
                        openssl_type, NULL, (unsigned char *) client_pub.data, client_pub.size);
                EXPECT_NOT_NULL(conn->kex_params.client_ecc_evp_params.evp_pkey);

                EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_HANDSHAKE_SECRET));
                EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.extract_secret,
                        handshake_secret.data, handshake_secret.size);
                EXPECT_EQUAL(conn->secrets.extract_secret_type, S2N_HANDSHAKE_SECRET);
            };

            /* Client */
            {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;
                EXPECT_OK(s2n_connection_set_test_early_secret(conn, &early_secret));

                conn->kex_params.server_ecc_evp_params.negotiated_curve = curve;
                conn->kex_params.server_ecc_evp_params.evp_pkey = EVP_PKEY_new_raw_public_key(
                        openssl_type, NULL, (unsigned char *) server_pub.data, server_pub.size);
                EXPECT_NOT_NULL(conn->kex_params.server_ecc_evp_params.evp_pkey);

                conn->kex_params.client_ecc_evp_params.negotiated_curve = curve;
                conn->kex_params.client_ecc_evp_params.evp_pkey = EVP_PKEY_new_raw_private_key(
                        openssl_type, NULL, (unsigned char *) client_priv.data, client_priv.size);
                EXPECT_NOT_NULL(conn->kex_params.client_ecc_evp_params.evp_pkey);

                EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_HANDSHAKE_SECRET));
                EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.extract_secret,
                        handshake_secret.data, handshake_secret.size);
                EXPECT_EQUAL(conn->secrets.extract_secret_type, S2N_HANDSHAKE_SECRET);
            };
        }
#endif

        /* Derive S2N_CLIENT_HANDSHAKE_TRAFFIC_SECRET */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {client}  derive secret "tls13 c hs traffic" (same as server)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {server}  derive secret "tls13 c hs traffic":
             *#
             *#       PRK (32 octets):  1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01
             *#          04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac
             **
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#       hash (32 octets):  86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
             *#          d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8
             *#
             *#       info (54 octets):  00 20 12 74 6c 73 31 33 20 63 20 68 73 20 74 72
             *#          61 66 66 69 63 20 86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58
             *#          ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8
             *#
             *#       expanded (32 octets):  b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e
             *#          2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21
             */
            S2N_BLOB_FROM_HEX(hash, "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed \
                         d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");
            S2N_BLOB_FROM_HEX(secret, "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e \
                         2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21");

            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {client}  calculate finished "tls13 finished" (same as server)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {client}  calculate finished "tls13 finished":
             *#
             *#       PRK (32 octets):  b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f
             *#          3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21
             **
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#       hash (0 octets):  (empty)
             *#
             *#       info (18 octets):  00 20 0e 74 6c 73 31 33 20 66 69 6e 69 73 68 65
             *#          64 00
             *#
             *#       expanded (32 octets):  b8 0a d0 10 15 fb 2f 0b d6 5f f7 d4 da 5d
             *#          6b f8 3f 84 82 1d 1f 87 fd c7 d3 c7 5b 5a 7b 42 d9 c4
             */
            S2N_BLOB_FROM_HEX(finished_key, "b8 0a d0 10 15 fb 2f 0b d6 5f f7 d4 da 5d \
                         6b f8 3f 84 82 1d 1f 87 fd c7 d3 c7 5b 5a 7b 42 d9 c4");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;
                EXPECT_OK(s2n_connection_set_test_handshake_secret(conn, &handshake_secret));
                EXPECT_OK(s2n_connection_set_test_transcript_hash(conn, SERVER_HELLO, &hash));

                EXPECT_OK(s2n_tls13_derive_secret(conn, S2N_HANDSHAKE_SECRET, S2N_CLIENT,
                        &derived_secret));

                EXPECT_EQUAL(derived_secret.size, secret.size);
                EXPECT_BYTEARRAY_EQUAL(derived_secret.data, secret.data, secret.size);
                EXPECT_BYTEARRAY_EQUAL(conn->handshake.client_finished,
                        finished_key.data, finished_key.size);
            }
        };

        /* Derive S2N_SERVER_HANDSHAKE_TRAFFIC_SECRET */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {client}  derive secret "tls13 s hs traffic" (same as server)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {server}  derive secret "tls13 s hs traffic":
             *#
             *#       PRK (32 octets):  1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01
             *#          04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac
             *#
             *#       hash (32 octets):  86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
             *#          d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8
             *#
             *#       info (54 octets):  00 20 12 74 6c 73 31 33 20 73 20 68 73 20 74 72
             *#          61 66 66 69 63 20 86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58
             *#          ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8
             *#
             *#       expanded (32 octets):  b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d
             *#          37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38
             */
            S2N_BLOB_FROM_HEX(hash, "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed \
                         d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");
            S2N_BLOB_FROM_HEX(secret, "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d \
                         37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38");

            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {client}  calculate finished "tls13 finished" (same as server)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {server}  calculate finished "tls13 finished":
             *#
             *#       PRK (32 octets):  b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4
             *#          e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38
             *#
             *#       hash (0 octets):  (empty)
             *#
             *#       info (18 octets):  00 20 0e 74 6c 73 31 33 20 66 69 6e 69 73 68 65
             *#          64 00
             *#
             *#       expanded (32 octets):  00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85
             *#          c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8
             */
            S2N_BLOB_FROM_HEX(finished_key, "00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 \
                         c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;
                EXPECT_OK(s2n_connection_set_test_handshake_secret(conn, &handshake_secret));
                EXPECT_OK(s2n_connection_set_test_transcript_hash(conn, SERVER_HELLO, &hash));

                EXPECT_OK(s2n_tls13_derive_secret(conn, S2N_HANDSHAKE_SECRET, S2N_SERVER,
                        &derived_secret));
                EXPECT_EQUAL(derived_secret.size, secret.size);
                EXPECT_BYTEARRAY_EQUAL(derived_secret.data, secret.data, secret.size);
                EXPECT_BYTEARRAY_EQUAL(conn->handshake.server_finished,
                        finished_key.data, finished_key.size);
            }
        };

        /**
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
         *= type=test
         *#    {client}  extract secret "master" (same as server master secret)
         *
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
         *= type=test
         *#    {server}  extract secret "master":
         *#
         *#       salt (32 octets):  43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5
         *#          31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4
         *#
         *#       IKM (32 octets):  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#          00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         **
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
         *= type=test
         *#       secret (32 octets):  18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a
         *#          47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19
         */
        S2N_BLOB_FROM_HEX(master_secret, "18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a \
                     47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19");

        /*
         * Extract MASTER_SECRET
         */
        {
            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;
                EXPECT_OK(s2n_connection_set_test_handshake_secret(conn, &handshake_secret));

                EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_MASTER_SECRET));
                EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.extract_secret,
                        master_secret.data, master_secret.size);
                EXPECT_EQUAL(conn->secrets.extract_secret_type, S2N_MASTER_SECRET);
            }
        };

        /* Derive CLIENT_APPLICATION_TRAFFIC_SECRET_0 */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {client}  derive secret "tls13 c ap traffic" (same as server)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {server}  derive secret "tls13 c ap traffic":
             *#
             *#       PRK (32 octets):  18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47
             *#          80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19
             *#
             *#       hash (32 octets):  96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a
             *#          00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13
             *#
             *#       info (54 octets):  00 20 12 74 6c 73 31 33 20 63 20 61 70 20 74 72
             *#          61 66 66 69 63 20 96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b
             *#          1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13
             *#
             *#       expanded (32 octets):  9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce
             *#          65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5
             */
            S2N_BLOB_FROM_HEX(hash, "96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a \
                         00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");
            S2N_BLOB_FROM_HEX(secret, "9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce \
                         65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;
                EXPECT_OK(s2n_connection_set_test_master_secret(conn, &master_secret));
                EXPECT_OK(s2n_connection_set_test_transcript_hash(conn, SERVER_FINISHED, &hash));

                EXPECT_OK(s2n_tls13_derive_secret(conn, S2N_MASTER_SECRET, S2N_CLIENT,
                        &derived_secret));
                EXPECT_EQUAL(derived_secret.size, secret.size);
                EXPECT_BYTEARRAY_EQUAL(derived_secret.data, secret.data, secret.size);
            }
        };

        /* Derive SERVER_APPLICATION_TRAFFIC_SECRET_0 */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {client}  derive secret "tls13 s ap traffic" (same as server)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {server}  derive secret "tls13 s ap traffic":
             *#
             *#       PRK (32 octets):  18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47
             *#          80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19
             *#
             *#       hash (32 octets):  96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a
             *#          00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13
             *#
             *#       info (54 octets):  00 20 12 74 6c 73 31 33 20 73 20 61 70 20 74 72
             *#          61 66 66 69 63 20 96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b
             *#          1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13
             **
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#       expanded (32 octets):  a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9
             *#          50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43
             */
            S2N_BLOB_FROM_HEX(hash, "96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a \
                         00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");
            S2N_BLOB_FROM_HEX(secret, "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 \
                         50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;
                EXPECT_OK(s2n_connection_set_test_master_secret(conn, &master_secret));
                EXPECT_OK(s2n_connection_set_test_transcript_hash(conn, SERVER_FINISHED, &hash));

                EXPECT_OK(s2n_tls13_derive_secret(conn, S2N_MASTER_SECRET, S2N_SERVER,
                        &derived_secret));

                EXPECT_EQUAL(derived_secret.size, secret.size);
                EXPECT_BYTEARRAY_EQUAL(derived_secret.data, secret.data, secret.size);
            }
        };

        /* Derive RESUMPTION_MASTER_SECRET */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {server}  derive secret "tls13 res master" (same as client)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {client}  derive secret "tls13 res master":
             *#
             *#       PRK (32 octets):  18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47
             *#          80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19
             *#
             *#       hash (32 octets):  20 91 45 a9 6e e8 e2 a1 22 ff 81 00 47 cc 95 26
             *#          84 65 8d 60 49 e8 64 29 42 6d b8 7c 54 ad 14 3d
             **
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#       info (52 octets):  00 20 10 74 6c 73 31 33 20 72 65 73 20 6d 61 73
             *#          74 65 72 20 20 91 45 a9 6e e8 e2 a1 22 ff 81 00 47 cc 95 26 84
             *#          65 8d 60 49 e8 64 29 42 6d b8 7c 54 ad 14 3d
             *#
             *#       expanded (32 octets):  7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41
             *#          b0 bf da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c
             */
            S2N_BLOB_FROM_HEX(hash, "20 91 45 a9 6e e8 e2 a1 22 ff 81 00 47 cc 95 26 \
                         84 65 8d 60 49 e8 64 29 42 6d b8 7c 54 ad 14 3d");
            S2N_BLOB_FROM_HEX(secret, "7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 \
                         b0 bf da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;
                EXPECT_OK(s2n_connection_set_test_master_secret(conn, &master_secret));
                EXPECT_OK(s2n_connection_set_test_transcript_hash(conn, CLIENT_FINISHED, &hash));

                EXPECT_OK(s2n_derive_resumption_master_secret(conn));
                EXPECT_EQUAL(derived_secret.size, secret.size);
                EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.resumption_master_secret,
                        secret.data, secret.size);
            }
        };

        /* Derive EXPORTER_MASTER_SECRET */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {client}  derive secret "tls13 exp master" (same as server)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {server}  derive secret "tls13 exp master":
             *#
             *#       PRK (32 octets):  18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47
             *#          80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19
             *#
             *#       hash (32 octets):  96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a
             *#          00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13
             *#
             **
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#       info (52 octets):  00 20 10 74 6c 73 31 33 20 65 78 70 20 6d 61 73
             *#          74 65 72 20 96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00
             *#          0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13
             *#
             *#       expanded (32 octets):  fe 22 f8 81 17 6e da 18 eb 8f 44 52 9e 67
             *#          92 c5 0c 9a 3f 89 45 2f 68 d8 ae 31 1b 43 09 d3 cf 50
             */
            S2N_BLOB_FROM_HEX(hash, "96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a \
                       00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");
            S2N_BLOB_FROM_HEX(secret, "fe 22 f8 81 17 6e da 18 eb 8f 44 52 9e 67 \
                       92 c5 0c 9a 3f 89 45 2f 68 d8 ae 31 1b 43 09 d3 cf 50");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;
                EXPECT_OK(s2n_connection_set_test_master_secret(conn, &master_secret));
                EXPECT_OK(s2n_connection_set_test_transcript_hash(conn, SERVER_FINISHED, &hash));

                EXPECT_OK(s2n_derive_exporter_master_secret(conn, &derived_secret));
                EXPECT_EQUAL(derived_secret.size, secret.size);
                EXPECT_BYTEARRAY_EQUAL(derived_secret.data, secret.data, secret.size);
            }
        };
    };

    /* Resumed 0-RTT Handshake */
    {
        /**
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-4
         *= type=test
         *#    {server}  extract secret "early" (same as client early secret)
         *
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-4
         *= type=test
         *#    {client}  extract secret "early":
         *#
         *#       salt:  0 (all zero octets)
         *#
         *#       IKM (32 octets):  4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c a4 c5
         *#          85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3
         *#
         *#       secret (32 octets):  9b 21 88 e9 b2 fc 6d 64 d7 1d c3 29 90 0e 20
         *#          bb 41 91 50 00 f6 78 aa 83 9c bb 79 7c b7 d8 33 2c
         */
        S2N_BLOB_FROM_HEX(psk_secret, "4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c a4 c5 \
                     85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3");
        S2N_BLOB_FROM_HEX(early_secret, "9b 21 88 e9 b2 fc 6d 64 d7 1d c3 29 90 0e 20 \
                     bb 41 91 50 00 f6 78 aa 83 9c bb 79 7c b7 d8 33 2c");

        /* Extract EARLY_SECRET */
        {
            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;

                DEFER_CLEANUP(struct s2n_psk *psk = s2n_test_psk_new(conn), s2n_psk_free);
                EXPECT_NOT_NULL(psk);
                EXPECT_SUCCESS(s2n_psk_set_secret(psk, psk_secret.data, psk_secret.size));

                /* Early secret calculated from PSK */
                EXPECT_OK(s2n_extract_early_secret(psk));
                EXPECT_EQUAL(psk->early_secret.size, early_secret.size);
                EXPECT_BYTEARRAY_EQUAL(psk->early_secret.data, early_secret.data, early_secret.size);

                /* Early secret retrieved and saved for connection */
                conn->psk_params.chosen_psk = psk;
                EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_EARLY_SECRET));
                EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.extract_secret,
                        early_secret.data, early_secret.size);
                EXPECT_EQUAL(conn->secrets.extract_secret_type, S2N_EARLY_SECRET);
            }
        };

        /* Derive BINDER_KEY */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-4
             *= type=test
             *#       PRK (32 octets):  69 fe 13 1a 3b ba d5 d6 3c 64 ee bc c3 0e 39 5b
             *#          9d 81 07 72 6a 13 d0 74 e3 89 db c8 a4 e4 72 56
             */
            S2N_BLOB_FROM_HEX(binder_key, "69 fe 13 1a 3b ba d5 d6 3c 64 ee bc c3 0e 39 5b \
                         9d 81 07 72 6a 13 d0 74 e3 89 db c8 a4 e4 72 56");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;

                DEFER_CLEANUP(struct s2n_psk *psk = s2n_test_psk_new(conn), s2n_psk_free);
                EXPECT_NOT_NULL(psk);
                psk->type = S2N_PSK_TYPE_RESUMPTION;
                EXPECT_SUCCESS(s2n_psk_set_secret(psk, psk_secret.data, psk_secret.size));

                EXPECT_OK(s2n_derive_binder_key(psk, &derived_secret));
                EXPECT_BYTEARRAY_EQUAL(psk->early_secret.data, early_secret.data, early_secret.size);
                EXPECT_EQUAL(derived_secret.size, binder_key.size);
                EXPECT_BYTEARRAY_EQUAL(derived_secret.data, binder_key.data, binder_key.size);
            }
        };

        /* Derive CLIENT_EARLY_TRAFFIC_SECRET */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-4
             *= type=test
             *#    {server}  derive secret "tls13 c e traffic" (same as client)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-4
             *= type=test
             *#    {client}  derive secret "tls13 c e traffic":
             *#
             *#       PRK (32 octets):  9b 21 88 e9 b2 fc 6d 64 d7 1d c3 29 90 0e 20 bb
             *#          41 91 50 00 f6 78 aa 83 9c bb 79 7c b7 d8 33 2c
             *#
             *#       hash (32 octets):  08 ad 0f a0 5d 7c 72 33 b1 77 5b a2 ff 9f 4c 5b
             *#          8b 59 27 6b 7f 22 7f 13 a9 76 24 5f 5d 96 09 13
             *#
             *#       info (53 octets):  00 20 11 74 6c 73 31 33 20 63 20 65 20 74 72 61
             *#          66 66 69 63 20 08 ad 0f a0 5d 7c 72 33 b1 77 5b a2 ff 9f 4c 5b
             *#          8b 59 27 6b 7f 22 7f 13 a9 76 24 5f 5d 96 09 13
             *#
             *#       expanded (32 octets):  3f bb e6 a6 0d eb 66 c3 0a 32 79 5a ba 0e
             *#          ff 7e aa 10 10 55 86 e7 be 5c 09 67 8d 63 b6 ca ab 62
             */
            S2N_BLOB_FROM_HEX(hash, "08 ad 0f a0 5d 7c 72 33 b1 77 5b a2 ff 9f 4c 5b \
                         8b 59 27 6b 7f 22 7f 13 a9 76 24 5f 5d 96 09 13");
            S2N_BLOB_FROM_HEX(secret, "3f bb e6 a6 0d eb 66 c3 0a 32 79 5a ba 0e \
                         ff 7e aa 10 10 55 86 e7 be 5c 09 67 8d 63 b6 ca ab 62");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;
                EXPECT_OK(s2n_connection_set_test_early_secret(conn, &early_secret));
                EXPECT_OK(s2n_connection_set_test_transcript_hash(conn, CLIENT_HELLO, &hash));

                EXPECT_OK(s2n_tls13_derive_secret(conn, S2N_EARLY_SECRET, S2N_CLIENT,
                        &derived_secret));
                EXPECT_EQUAL(derived_secret.size, secret.size);
                EXPECT_BYTEARRAY_EQUAL(derived_secret.data, secret.data, secret.size);
            }
        };
    };

    END_TEST();
}
