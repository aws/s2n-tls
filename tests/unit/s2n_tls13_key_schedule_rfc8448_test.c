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

#include "tls/s2n_tls13_key_schedule.h"
#include "tls/s2n_tls13_secrets.h"

#include "tls/s2n_cipher_suites.h"

struct s2n_cipher_suite *cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

const s2n_mode modes[] = { S2N_CLIENT, S2N_SERVER };

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* The RFC values use x25519,
     * which is only supported via EVP APIs.
     */
    if (!s2n_is_evp_apis_supported()) {
        END_TEST();
    }

    /*
     * Simple 1-RTT Handshake
     */
    {
        const uint32_t one_rtt_handshake_type = NEGOTIATED | FULL_HANDSHAKE;
        const int one_rtt_message_nums[] = {
                [SERVER_HELLO] = 1,
                [SERVER_FINISHED] = 5,
                [CLIENT_FINISHED] = 6,
        };

        /**
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
         *#    {client}  extract secret "handshake" (same as server handshake
         *# secret)
         *
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
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

        /**
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
         *#       hash (32 octets):  86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
         *#          d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8
         */
        S2N_BLOB_FROM_HEX(server_hello_hash, "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed \
                     d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");

        /* Derive server handshake traffic keys */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *#    {client}  derive read traffic keys for handshake data (same as server
             *#        handshake data write traffic keys)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *#    {server}  derive write traffic keys for handshake data:
             *#
             *#       PRK (32 octets):  b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4
             *#          e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38
             *#
             *#       key info (13 octets):  00 10 09 74 6c 73 31 33 20 6b 65 79 00
             *#
             *#       key expanded (16 octets):  3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e
             *#          e4 03 bc
             *#
             *#       iv info (12 octets):  00 0c 08 74 6c 73 31 33 20 69 76 00
             *#
             *#       iv expanded (12 octets):  5d 31 3e b2 67 12 76 ee 13 00 0b 30
             */
            S2N_BLOB_FROM_HEX(key, "3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e \
                         e4 03 bc");
            S2N_BLOB_FROM_HEX(iv, "5d 31 3e b2 67 12 76 ee 13 00 0b 30");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure.cipher_suite = cipher_suite;
                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_connection_set_handshake_secret(conn, &handshake_secret));
                EXPECT_MEMCPY_SUCCESS(conn->handshake.hashes->server_hello_digest,
                        server_hello_hash.data, server_hello_hash.size);

                conn->handshake.handshake_type = one_rtt_handshake_type;
                conn->handshake.message_number = one_rtt_message_nums[SERVER_HELLO];
                EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_HELLO);

                EXPECT_OK(s2n_tls13_key_schedule_update(conn));
                EXPECT_BYTEARRAY_EQUAL(conn->secure.server_implicit_iv, iv.data, iv.size);
            }
        }

        /* Derive client handshake traffic keys */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *#    {client}  derive write traffic keys for handshake data (same as
             *#       server handshake data read traffic keys)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *#    {server}  derive read traffic keys for handshake data:
             *#
             *#       PRK (32 octets):  b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f
             *#          3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21
             *#
             *#       key info (13 octets):  00 10 09 74 6c 73 31 33 20 6b 65 79 00
             *#
             *#       key expanded (16 octets):  db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50
             *#          25 8d 01
             *#
             *#       iv info (12 octets):  00 0c 08 74 6c 73 31 33 20 69 76 00
             *#
             *#       iv expanded (12 octets):  5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f
             */
            S2N_BLOB_FROM_HEX(key, "db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 \
                         25 8d 01");
            S2N_BLOB_FROM_HEX(iv, "5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure.cipher_suite = cipher_suite;
                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_connection_set_handshake_secret(conn, &handshake_secret));
                EXPECT_MEMCPY_SUCCESS(conn->handshake.hashes->server_hello_digest,
                        server_hello_hash.data, server_hello_hash.size);

                conn->handshake.handshake_type = one_rtt_handshake_type;
                conn->handshake.message_number = one_rtt_message_nums[SERVER_FINISHED];
                EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_FINISHED);

                EXPECT_OK(s2n_tls13_key_schedule_update(conn));
                EXPECT_BYTEARRAY_EQUAL(conn->secure.client_implicit_iv, iv.data, iv.size);
            }
        }

        /**
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
         *#    {client}  extract secret "master" (same as server master secret)
         *
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
         *#    {server}  extract secret "master":
         *#
         *#       salt (32 octets):  43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5
         *#          31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4
         *#
         *#       IKM (32 octets):  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#          00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         **
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
         *#       secret (32 octets):  18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a
         *#          47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19
         */
        S2N_BLOB_FROM_HEX(master_secret, "18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a \
                     47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19");

        /**
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
         *#       hash (32 octets):  96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a
         *#          00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13
         */
        S2N_BLOB_FROM_HEX(server_finished_hash, "96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a \
                     00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");

        /* Derive server application traffic keys */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *#    {client}  derive read traffic keys for application data (same as
             *#       server application data write traffic keys)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *#    {server}  derive write traffic keys for application data:
             *#
             *#       PRK (32 octets):  a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32
             *#          82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43
             *#
             *#       key info (13 octets):  00 10 09 74 6c 73 31 33 20 6b 65 79 00
             *#
             *#       key expanded (16 octets):  9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac
             *#          92 e3 56
             *#
             *#       iv info (12 octets):  00 0c 08 74 6c 73 31 33 20 69 76 00
             *#
             *#       iv expanded (12 octets):  cf 78 2b 88 dd 83 54 9a ad f1 e9 84
             */
            S2N_BLOB_FROM_HEX(key, "9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac \
                         92 e3 56");
            S2N_BLOB_FROM_HEX(iv, "cf 78 2b 88 dd 83 54 9a ad f1 e9 84");

            const message_type_t trigger_messages[] = {
                    [S2N_CLIENT] = CLIENT_FINISHED,
                    [S2N_SERVER] = SERVER_FINISHED,
            };

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                message_type_t trigger_message = trigger_messages[modes[i]];
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure.cipher_suite = cipher_suite;
                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_connection_set_master_secret(conn, &master_secret));
                EXPECT_MEMCPY_SUCCESS(conn->handshake.hashes->server_finished_digest,
                        server_finished_hash.data, server_finished_hash.size);

                conn->handshake.handshake_type = one_rtt_handshake_type;
                conn->handshake.message_number = one_rtt_message_nums[trigger_message];
                EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), trigger_message);

                EXPECT_OK(s2n_tls13_key_schedule_update(conn));
                EXPECT_BYTEARRAY_EQUAL(conn->secure.server_implicit_iv, iv.data, iv.size);
            }
        }

        /* Derive client application traffic keys */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *#    {server}  derive read traffic keys for application data (same as
             *#       client application data write traffic keys)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *#    {client}  derive write traffic keys for application data:
             *#
             *#       PRK (32 octets):  9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52
             *#          87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5
             *#
             *#       key info (13 octets):  00 10 09 74 6c 73 31 33 20 6b 65 79 00
             *#
             *#       key expanded (16 octets):  17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6
             *#          3f 50 51
             *#
             *#       iv info (12 octets):  00 0c 08 74 6c 73 31 33 20 69 76 00
             *#
             *#       iv expanded (12 octets):  5b 78 92 3d ee 08 57 90 33 e5 23 d9
             */
            S2N_BLOB_FROM_HEX(key, "17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 \
                         3f 50 51");
            S2N_BLOB_FROM_HEX(iv, "5b 78 92 3d ee 08 57 90 33 e5 23 d9");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure.cipher_suite = cipher_suite;
                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_connection_set_master_secret(conn, &master_secret));
                EXPECT_MEMCPY_SUCCESS(conn->handshake.hashes->server_finished_digest,
                        server_finished_hash.data, server_finished_hash.size);

                conn->handshake.handshake_type = one_rtt_handshake_type;
                conn->handshake.message_number = one_rtt_message_nums[CLIENT_FINISHED];
                EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), CLIENT_FINISHED);

                EXPECT_OK(s2n_tls13_key_schedule_update(conn));
                EXPECT_BYTEARRAY_EQUAL(conn->secure.client_implicit_iv, iv.data, iv.size);
            }
        }
    }

    /* Resumed 0-RTT Handshake */
    {
        const uint32_t resumed_handshake_type = NEGOTIATED | WITH_EARLY_DATA;
        const int resumed_message_nums[] = {
                [CLIENT_HELLO] = 0,
                [SERVER_FINISHED] = 3,
        };

        /**
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-4
         *#    {server}  extract secret "early" (same as client early secret)
         *
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-4
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
        S2N_BLOB_FROM_HEX(early_secret, "9b 21 88 e9 b2 fc 6d 64 d7 1d c3 29 90 0e 20 \
                     bb 41 91 50 00 f6 78 aa 83 9c bb 79 7c b7 d8 33 2c");

        /**
         *= https://www.rfc-editor.org/rfc/rfc8448.html#section-4
         *#       hash (32 octets):  08 ad 0f a0 5d 7c 72 33 b1 77 5b a2 ff 9f 4c 5b
         *#          8b 59 27 6b 7f 22 7f 13 a9 76 24 5f 5d 96 09 13
         */
        S2N_BLOB_FROM_HEX(client_hello_hash, "08 ad 0f a0 5d 7c 72 33 b1 77 5b a2 ff 9f 4c 5b \
                     8b 59 27 6b 7f 22 7f 13 a9 76 24 5f 5d 96 09 13");

        /* Derive early application traffic keys */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-4
             *#    {server}  derive read traffic keys for early application data (same
             *#       as client early application data write traffic keys)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-4
             *#    {client}  derive write traffic keys for early application data:
             *#
             *#       PRK (32 octets):  3f bb e6 a6 0d eb 66 c3 0a 32 79 5a ba 0e ff 7e
             *#          aa 10 10 55 86 e7 be 5c 09 67 8d 63 b6 ca ab 62
             *#
             *#       key info (13 octets):  00 10 09 74 6c 73 31 33 20 6b 65 79 00
             *#
             *#       key expanded (16 octets):  92 02 05 a5 b7 bf 21 15 e6 fc 5c 29 42
             *#          83 4f 54
             *#
             *#       iv info (12 octets):  00 0c 08 74 6c 73 31 33 20 69 76 00
             *#
             *#       iv expanded (12 octets):  6d 47 5f 09 93 c8 e5 64 61 0d b2 b9
             */
            S2N_BLOB_FROM_HEX(key, "92 02 05 a5 b7 bf 21 15 e6 fc 5c 29 42 \
                         83 4f 54");
            S2N_BLOB_FROM_HEX(iv, "6d 47 5f 09 93 c8 e5 64 61 0d b2 b9");

            const message_type_t trigger_messages[] = {
                    [S2N_CLIENT] = CLIENT_HELLO,
                    [S2N_SERVER] = SERVER_FINISHED,
            };

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                message_type_t trigger_message = trigger_messages[modes[i]];
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure.cipher_suite = cipher_suite;
                conn->actual_protocol_version = S2N_TLS13;
                conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
                EXPECT_OK(s2n_connection_set_early_secret(conn, &early_secret));
                EXPECT_MEMCPY_SUCCESS(conn->handshake.hashes->client_hello_digest,
                        client_hello_hash.data, client_hello_hash.size);

                /*
                 * The handshake secret isn't factored into the early data key,
                 * but needs to be set to something because the server derives the handshake
                 * secret before it calculates the early data key.
                 */
                EXPECT_OK(s2n_connection_set_handshake_secret(conn, &(struct s2n_blob){ 0 }));

                conn->handshake.handshake_type = resumed_handshake_type;
                conn->handshake.message_number = resumed_message_nums[trigger_message];
                EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), trigger_message);

                EXPECT_OK(s2n_tls13_key_schedule_update(conn));
                EXPECT_TRUE(conn->client == &conn->secure || conn->client == &conn->secure);
                EXPECT_BYTEARRAY_EQUAL(conn->secure.client_implicit_iv, iv.data, iv.size);
            }
        }
    }

    END_TEST();
}
