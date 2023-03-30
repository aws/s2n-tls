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

const s2n_mode modes[] = { S2N_SERVER, S2N_CLIENT };

static uint8_t test_send_key[S2N_TLS_AES_256_GCM_KEY_LEN] = { 0 };
static int s2n_test_set_send_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    POSIX_ENSURE_REF(key);
    POSIX_ENSURE_REF(in);
    POSIX_CHECKED_MEMCPY(test_send_key, in->data, in->size);
    return S2N_SUCCESS;
}

static uint8_t test_recv_key[S2N_TLS_AES_256_GCM_KEY_LEN] = { 0 };
static int s2n_test_set_recv_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    POSIX_ENSURE_REF(key);
    POSIX_ENSURE_REF(in);
    POSIX_CHECKED_MEMCPY(test_recv_key, in->data, in->size);
    return S2N_SUCCESS;
}

#define EXPECT_IVS_EQUAL(conn, iv, iv_mode)                                               \
    if ((iv_mode) == S2N_CLIENT) {                                                        \
        EXPECT_BYTEARRAY_EQUAL((conn)->secure->client_implicit_iv, (iv).data, (iv).size); \
    } else {                                                                              \
        EXPECT_BYTEARRAY_EQUAL((conn)->secure->server_implicit_iv, (iv).data, (iv).size); \
    }

#define EXPECT_KEYS_EQUAL(conn, key, key_mode)                         \
    if ((conn)->mode == (key_mode)) {                                  \
        EXPECT_BYTEARRAY_EQUAL(test_send_key, (key).data, (key).size); \
    } else {                                                           \
        EXPECT_BYTEARRAY_EQUAL(test_recv_key, (key).data, (key).size); \
    }

static S2N_RESULT s2n_set_test_secret(struct s2n_connection *conn, uint8_t *secret_bytes, const struct s2n_blob secret)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(secret_bytes);
    RESULT_CHECKED_MEMCPY(secret_bytes, secret.data, secret.size);
    /*
     * Mark the last secret extracted as the master secret to
     * indicate that all secrets have already been derived.
     * This test is interested in keys, not secrets.
     */
    conn->secrets.extract_secret_type = S2N_MASTER_SECRET;
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* The RFC values use x25519,
     * which is only supported via EVP APIs.
     */
    if (!s2n_is_evp_apis_supported()) {
        END_TEST();
    }

    /* Once a key is set via the standard ciphers, we are unable to retrieve it.
     * So use a custom cipher to store the keys for later verification.
     */
    struct s2n_cipher_suite test_cipher_suite = s2n_tls13_aes_128_gcm_sha256;
    struct s2n_record_algorithm test_record_alg = *(test_cipher_suite.record_alg);
    struct s2n_cipher test_cipher = *(test_record_alg.cipher);
    test_cipher.set_decryption_key = &s2n_test_set_recv_key;
    test_cipher.set_encryption_key = &s2n_test_set_send_key;
    test_record_alg.cipher = &test_cipher;
    test_cipher_suite.record_alg = &test_record_alg;
    struct s2n_cipher_suite *cipher_suite = &test_cipher_suite;

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

        /* Derive server handshake traffic keys */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {client}  derive read traffic keys for handshake data (same as server
             *#        handshake data write traffic keys)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
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
            S2N_BLOB_FROM_HEX(secret, "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 \
                         e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38");
            S2N_BLOB_FROM_HEX(key, "3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e \
                         e4 03 bc");
            S2N_BLOB_FROM_HEX(iv, "5d 31 3e b2 67 12 76 ee 13 00 0b 30");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;
                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_set_test_secret(conn, conn->secrets.version.tls13.server_handshake_secret, secret));

                conn->handshake.handshake_type = one_rtt_handshake_type;
                conn->handshake.message_number = one_rtt_message_nums[SERVER_HELLO];
                EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_HELLO);
                EXPECT_OK(s2n_tls13_key_schedule_update(conn));

                EXPECT_IVS_EQUAL(conn, iv, S2N_SERVER);
                EXPECT_KEYS_EQUAL(conn, key, S2N_SERVER);
            }
        };

        /* Derive client handshake traffic keys */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {client}  derive write traffic keys for handshake data (same as
             *#       server handshake data read traffic keys)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
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
            S2N_BLOB_FROM_HEX(secret, "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f \
                         3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21");
            S2N_BLOB_FROM_HEX(key, "db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 \
                         25 8d 01");
            S2N_BLOB_FROM_HEX(iv, "5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;
                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
                EXPECT_OK(s2n_set_test_secret(conn, conn->secrets.version.tls13.client_handshake_secret, secret));

                conn->handshake.handshake_type = one_rtt_handshake_type;
                conn->handshake.message_number = one_rtt_message_nums[SERVER_FINISHED];
                EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_FINISHED);
                EXPECT_OK(s2n_tls13_key_schedule_update(conn));

                EXPECT_IVS_EQUAL(conn, iv, S2N_CLIENT);
                EXPECT_KEYS_EQUAL(conn, key, S2N_CLIENT);
            }
        };

        /* Derive server application traffic keys */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {client}  derive read traffic keys for application data (same as
             *#       server application data write traffic keys)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
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
            S2N_BLOB_FROM_HEX(secret, "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 \
                         82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43");
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
                conn->secure->cipher_suite = cipher_suite;
                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
                EXPECT_OK(s2n_set_test_secret(conn, conn->secrets.version.tls13.server_app_secret, secret));

                conn->handshake.handshake_type = one_rtt_handshake_type;
                conn->handshake.message_number = one_rtt_message_nums[trigger_message];
                EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), trigger_message);
                EXPECT_OK(s2n_tls13_key_schedule_update(conn));

                EXPECT_IVS_EQUAL(conn, iv, S2N_SERVER);
                EXPECT_KEYS_EQUAL(conn, key, S2N_SERVER);
            }
        };

        /* Derive client application traffic keys */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
             *#    {server}  derive read traffic keys for application data (same as
             *#       client application data write traffic keys)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-3
             *= type=test
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
            S2N_BLOB_FROM_HEX(secret, "9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 \
                         87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5");
            S2N_BLOB_FROM_HEX(key, "17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 \
                         3f 50 51");
            S2N_BLOB_FROM_HEX(iv, "5b 78 92 3d ee 08 57 90 33 e5 23 d9");

            for (size_t i = 0; i < s2n_array_len(modes); i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(modes[i]), s2n_connection_ptr_free);
                conn->secure->cipher_suite = cipher_suite;
                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
                EXPECT_OK(s2n_set_test_secret(conn, conn->secrets.version.tls13.client_app_secret, secret));

                conn->handshake.handshake_type = one_rtt_handshake_type;
                conn->handshake.message_number = one_rtt_message_nums[CLIENT_FINISHED];
                EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), CLIENT_FINISHED);
                EXPECT_OK(s2n_tls13_key_schedule_update(conn));

                EXPECT_IVS_EQUAL(conn, iv, S2N_CLIENT);
                EXPECT_KEYS_EQUAL(conn, key, S2N_CLIENT);
            }
        };
    };

    /* Resumed 0-RTT Handshake */
    {
        const uint32_t resumed_handshake_type = NEGOTIATED | WITH_EARLY_DATA;
        const int resumed_message_nums[] = {
            [CLIENT_HELLO] = 0,
            [SERVER_FINISHED] = 3,
        };

        /* Derive early application traffic keys */
        {
            /**
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-4
             *= type=test
             *#    {server}  derive read traffic keys for early application data (same
             *#       as client early application data write traffic keys)
             *
             *= https://www.rfc-editor.org/rfc/rfc8448.html#section-4
             *= type=test
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
            S2N_BLOB_FROM_HEX(secret, "3f bb e6 a6 0d eb 66 c3 0a 32 79 5a ba 0e ff 7e \
                         aa 10 10 55 86 e7 be 5c 09 67 8d 63 b6 ca ab 62");
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
                conn->secure->cipher_suite = cipher_suite;
                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
                conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
                EXPECT_OK(s2n_set_test_secret(conn, conn->secrets.version.tls13.client_early_secret, secret));

                conn->handshake.handshake_type = resumed_handshake_type;
                conn->handshake.message_number = resumed_message_nums[trigger_message];
                EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), trigger_message);
                EXPECT_OK(s2n_tls13_key_schedule_update(conn));

                EXPECT_IVS_EQUAL(conn, iv, S2N_CLIENT);
                EXPECT_KEYS_EQUAL(conn, key, S2N_CLIENT);
            }
        };
    };

    END_TEST();
}
