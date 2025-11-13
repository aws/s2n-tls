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

#include <stdio.h>
#include <string.h>

#include "api/s2n.h"
#include "crypto/s2n_libcrypto.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
/* To gain access to handshake_read and handshake_write */
#include "tls/s2n_handshake_io.c"

#define TEST_BLOB_SIZE 64

int s2n_prf(struct s2n_connection *conn, struct s2n_blob *secret,
        struct s2n_blob *label, struct s2n_blob *seed_a,
        struct s2n_blob *seed_b, struct s2n_blob *seed_c, struct s2n_blob *out);
S2N_RESULT s2n_prf_get_digest_for_ems(struct s2n_connection *conn,
        struct s2n_blob *message, s2n_hash_algorithm hash_alg, struct s2n_blob *output);
S2N_RESULT s2n_prf_tls_extended_master_secret(struct s2n_connection *conn,
        struct s2n_blob *premaster_secret, struct s2n_blob *session_hash, struct s2n_blob *sha1_hash);
int s2n_prf_tls_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret);

/*
 * Grabbed from gnutls-cli --insecure -d 9 www.example.com --ciphers AES --macs SHA --protocols TLS1.0
 *
 * |<9>| INT: PREMASTER SECRET[48]: 0301bebf2a5707c7bda6bfe5a8971a351a9ebd019de412212da021fd802e03f49f231d4e959c7352679f892f9d7f9748
 * |<9>| INT: CLIENT RANDOM[32]: 537eefc1e720b311ff8483d057ae750a3667af9d5b496cc0d2edfb0dd309a286
 * |<9>| INT: SERVER RANDOM[32]: 537eefc29f337c5eedacd00a1889b031261701872d666a74fa999dc13bcd8821
 * |<9>| INT: MASTER SECRET: c8c610686237cd024a2d8e0391f61a8a4464c2c9576ea2b5ccf3af68139ec07c6a1720097063de968f2341f77b837120
 */
int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    S2N_BLOB_FROM_HEX(premaster_secret_in,
            "0301bebf2a5707c7bda6bfe5a8971a351a9ebd019de412212da021fd802e03f49f231d4e959c7352679f892f9d7f9748");
    S2N_BLOB_FROM_HEX(client_random_in,
            "537eefc1e720b311ff8483d057ae750a3667af9d5b496cc0d2edfb0dd309a286");
    S2N_BLOB_FROM_HEX(server_random_in,
            "537eefc29f337c5eedacd00a1889b031261701872d666a74fa999dc13bcd8821");
    S2N_BLOB_FROM_HEX(master_secret_in,
            "c8c610686237cd024a2d8e0391f61a8a4464c2c9576ea2b5ccf3af68139ec07c6a1720097063de968f2341f77b837120");

    /* s2n_prf tests */
    {
        uint8_t secret_bytes[TEST_BLOB_SIZE] = "secret";
        struct s2n_blob secret = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&secret, secret_bytes, sizeof(secret_bytes)));

        uint8_t label_bytes[TEST_BLOB_SIZE] = "label";
        struct s2n_blob label = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&label, label_bytes, sizeof(label_bytes)));

        uint8_t seed_a_bytes[TEST_BLOB_SIZE] = "seed a";
        struct s2n_blob seed_a = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&seed_a, seed_a_bytes, sizeof(seed_a_bytes)));

        uint8_t seed_b_bytes[TEST_BLOB_SIZE] = "seed b";
        struct s2n_blob seed_b = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&seed_b, seed_b_bytes, sizeof(seed_b_bytes)));

        uint8_t seed_c_bytes[TEST_BLOB_SIZE] = "seed c";
        struct s2n_blob seed_c = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&seed_c, seed_c_bytes, sizeof(seed_c_bytes)));

        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            s2n_stack_blob(out, TEST_BLOB_SIZE, TEST_BLOB_SIZE);

            EXPECT_FAILURE_WITH_ERRNO(s2n_prf(NULL, &secret, &label, &seed_a, &seed_b, &seed_c, &out),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_prf(connection, NULL, &label, &seed_a, &seed_b, &seed_c, &out),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_prf(connection, &secret, NULL, &seed_a, &seed_b, &seed_c, &out),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_prf(connection, &secret, &label, &seed_a, &seed_b, &seed_c, NULL),
                    S2N_ERR_NULL);

            /* seed_a is required */
            EXPECT_FAILURE_WITH_ERRNO(s2n_prf(connection, &secret, &label, NULL, &seed_b, &seed_c, &out),
                    S2N_ERR_PRF_INVALID_SEED);

            /* seed_b and seed_c are optional */
            EXPECT_SUCCESS(s2n_prf(connection, &secret, &label, &seed_a, NULL, NULL, &out));

            /* seed_b is required if seed_c is provided */
            EXPECT_FAILURE_WITH_ERRNO(s2n_prf(connection, &secret, &label, &seed_a, NULL, &seed_c, &out),
                    S2N_ERR_PRF_INVALID_SEED);

            /* seed_c is optional */
            EXPECT_SUCCESS(s2n_prf(connection, &secret, &label, &seed_a, &seed_b, NULL, &out));
        }

        /* Test: secret and label */
        {
            struct s2n_blob empty = { 0 };
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->actual_protocol_version = S2N_TLS11;

            const char *expected_hex =
                    "d6 4d 7e e1 f3 ca ff a0 d4 7e 84 18 ff 64 97 d8"
                    "56 4d d1 99 5e ea 53 0d 29 b0 42 68 89 45 f3 58 86"
                    "f5 4b 12 ff b3 83 87 80 d5 ba 7d f6 26 10 a5 cc 39"
                    "d9 e7 37 6e eb 28 8e 21 29 53 13 54 f5 f6";
            S2N_BLOB_FROM_HEX(expected, expected_hex);

            s2n_stack_blob(out, TEST_BLOB_SIZE, TEST_BLOB_SIZE);
            EXPECT_SUCCESS(s2n_prf(conn, &secret, &label, &empty, NULL, NULL, &out));
            EXPECT_EQUAL(out.size, expected.size);
            EXPECT_BYTEARRAY_EQUAL(out.data, expected.data, expected.size);
        }

        /* Test: secret, label, and seed_a */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->actual_protocol_version = S2N_TLS11;

            const char *expected_hex =
                    "4e f2 13 65 22 07 f1 e5 86 dc 03 aa 60 a2 c9 5c"
                    "ab 05 5e 43 f0 c8 3a 70 6c f4 be 21 44 9e b8 45 70"
                    "d9 e8 e1 83 3b f7 65 dd e9 d1 ea ae 14 f7 73 c5 47"
                    "57 da 0a a8 5f cc 75 ff b2 9e 3d 02 01 e9";
            S2N_BLOB_FROM_HEX(expected, expected_hex);

            s2n_stack_blob(out, TEST_BLOB_SIZE, TEST_BLOB_SIZE);
            EXPECT_SUCCESS(s2n_prf(conn, &secret, &label, &seed_a, NULL, NULL, &out));
            EXPECT_EQUAL(out.size, expected.size);
            EXPECT_BYTEARRAY_EQUAL(out.data, expected.data, expected.size);
        }

        /* Test: secret, label, seed_a, and seed_b */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->actual_protocol_version = S2N_TLS11;

            const char *expected_hex =
                    "45 0b b0 da 24 d5 23 05 b6 00 f9 1c 71 6f ca 40"
                    "54 ba 1b 6c 91 43 77 9c 0f 6f 2c e6 e4 24 30 ee b3"
                    "fc 83 85 3a 02 60 1e 37 2c 2c ee d3 b1 8a 6a cc 75"
                    "d9 84 87 42 d8 b6 a9 9c 1b f8 72 8c 6b 71";
            S2N_BLOB_FROM_HEX(expected, expected_hex);

            s2n_stack_blob(out, TEST_BLOB_SIZE, TEST_BLOB_SIZE);
            EXPECT_SUCCESS(s2n_prf(conn, &secret, &label, &seed_a, &seed_b, NULL, &out));
            EXPECT_EQUAL(out.size, expected.size);
            EXPECT_BYTEARRAY_EQUAL(out.data, expected.data, expected.size);
        }

        /* Test: all inputs */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->actual_protocol_version = S2N_TLS11;

            const char *expected_hex =
                    "4f b6 e2 ac d0 68 dc 55 70 43 ab 98 f6 23 a8 93"
                    "6b f2 0f 48 1c 74 50 7e a0 f2 ef 49 53 a6 b0 56 84"
                    "fe 2e a9 76 31 50 44 f7 8d e7 3d 52 97 ce 36 82 a8"
                    "d7 27 59 f7 7a 73 19 06 6c 0a 1a df 68 c6";
            S2N_BLOB_FROM_HEX(expected, expected_hex);

            s2n_stack_blob(out, TEST_BLOB_SIZE, TEST_BLOB_SIZE);
            EXPECT_SUCCESS(s2n_prf(conn, &secret, &label, &seed_a, &seed_b, &seed_c, &out));
            EXPECT_EQUAL(out.size, expected.size);
            EXPECT_BYTEARRAY_EQUAL(out.data, expected.data, expected.size);
        }

        /* Test: cipher specific digest */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384;

            const char *expected_hex =
                    "5b 54 71 ec b9 8a 49 ce f1 6a d9 31 cf c9 76 be"
                    "5a e6 25 bd a3 45 69 45 8c 6c 1a a1 98 06 d9 0d cc"
                    "c8 cd 7c aa d7 e2 59 25 4b 36 ff f7 01 a6 7e 89 22"
                    "0f bd 06 15 bf 9d 7e d1 53 45 a3 1b 36 da";
            S2N_BLOB_FROM_HEX(expected, expected_hex);

            s2n_stack_blob(out, TEST_BLOB_SIZE, TEST_BLOB_SIZE);
            EXPECT_SUCCESS(s2n_prf(conn, &secret, &label, &seed_a, &seed_b, &seed_c, &out));
            EXPECT_EQUAL(out.size, expected.size);
            EXPECT_BYTEARRAY_EQUAL(out.data, expected.data, expected.size);
        }

        /* Test: large seeds fail for openssl-3.0-fips */
        if (s2n_libcrypto_is_openssl_fips()) {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->actual_protocol_version = S2N_TLS11;

            DEFER_CLEANUP(struct s2n_blob small_seed = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&small_seed, 30));

            DEFER_CLEANUP(struct s2n_blob medium_seed = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&medium_seed, 300));

            DEFER_CLEANUP(struct s2n_blob large_seed = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&large_seed, 3000));

            s2n_stack_blob(out, TEST_BLOB_SIZE, TEST_BLOB_SIZE);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_prf(conn, &secret, &small_seed, &small_seed, &small_seed, &large_seed, &out),
                    S2N_ERR_PRF_INVALID_SEED);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_prf(conn, &secret, &medium_seed, &medium_seed, &medium_seed, &medium_seed, &out),
                    S2N_ERR_PRF_INVALID_SEED);
            EXPECT_SUCCESS(s2n_prf(conn, &secret,
                    &small_seed, &small_seed, &small_seed, &small_seed, &out));
        }

        /* The custom PRF implementation is used when s2n-tls is not operating in FIPS mode */
        if (!s2n_is_in_fips_mode()) {
            DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);

            uint8_t zeros[S2N_MAX_DIGEST_LEN] = { 0 };
            EXPECT_EQUAL(memcmp(connection->prf_space->digest0, zeros, S2N_MAX_DIGEST_LEN), 0);

            s2n_stack_blob(out, TEST_BLOB_SIZE, TEST_BLOB_SIZE);
            EXPECT_SUCCESS(s2n_prf(connection, &secret, &label, &seed_a, &seed_b, &seed_c, &out));

            /* The custom PRF implementation should modify the digest fields in the prf_space */
            EXPECT_NOT_EQUAL(memcmp(connection->prf_space->digest0, zeros, S2N_MAX_DIGEST_LEN), 0);
        }

        /* The libcrypto PRF implementation is used when s2n-tls is in FIPS mode */
        if (s2n_is_in_fips_mode()) {
            DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);

            uint8_t zeros[S2N_MAX_DIGEST_LEN] = { 0 };
            EXPECT_EQUAL(memcmp(connection->prf_space->digest0, zeros, S2N_MAX_DIGEST_LEN), 0);

            s2n_stack_blob(out, TEST_BLOB_SIZE, TEST_BLOB_SIZE);
            EXPECT_SUCCESS(s2n_prf(connection, &secret, &label, &seed_a, &seed_b, &seed_c, &out));

            /* The libcrypto PRF implementation will not modify the digest fields in the prf_space */
            EXPECT_EQUAL(memcmp(connection->prf_space->digest0, zeros, S2N_MAX_DIGEST_LEN), 0);
        }
    }

    /* s2n_tls_prf_master_secret */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        /* Check the most common PRF */
        conn->actual_protocol_version = S2N_TLS11;

        EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls12.rsa_premaster_secret, premaster_secret_in.data, premaster_secret_in.size);
        EXPECT_MEMCPY_SUCCESS(conn->client_hello.client_random, client_random_in.data, client_random_in.size);
        EXPECT_MEMCPY_SUCCESS(conn->handshake_params.server_random, server_random_in.data, server_random_in.size);

        struct s2n_blob pms = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&pms, conn->secrets.version.tls12.rsa_premaster_secret, sizeof(conn->secrets.version.tls12.rsa_premaster_secret)));
        EXPECT_SUCCESS(s2n_prf_tls_master_secret(conn, &pms));
        EXPECT_EQUAL(memcmp(conn->secrets.version.tls12.master_secret, master_secret_in.data, master_secret_in.size), 0);
    };

    /* s2n_tls_prf_extended_master_secret */
    {
        /* The test premaster secret, hash digest, and resulting
         * extended master secret were pulled from an OpenSSL TLS1.2 EMS session
         * using the s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384 ciphersuite.
         */
        S2N_BLOB_FROM_HEX(premaster_secret,
                "05e12675c9264d82b53fa15d589c829af9be1ae3d881ab0b023b7b8cad8bc058");

        S2N_BLOB_FROM_HEX(hash_digest,
                "e6cbbaa03909ea387714fe70c07546086dedfcee086fd2985dfdd50924393619"
                "009115758e490e2e3b0c13bebdad5fbb");

        S2N_BLOB_FROM_HEX(extended_master_secret,
                "aef116e65e2cd77d4e96b1ceeadb7912ddd9aaf3a907aa3344ec3a2de6cc3b69"
                "9ca768fe389eab3b53c98d8ccd830b06");

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        conn->actual_protocol_version = S2N_TLS12;
        conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384;

        /**
         *= https://www.rfc-editor.org/rfc/rfc7627#section-4
         *= type=test
         *# When the extended master secret extension is negotiated in a full
         *# handshake, the "master_secret" is computed as
         *#
         *# master_secret = PRF(pre_master_secret, "extended master secret",
         *#                    session_hash)
         *#                    [0..47];
         */
        EXPECT_OK(s2n_prf_tls_extended_master_secret(conn, &premaster_secret, &hash_digest, NULL));
        EXPECT_BYTEARRAY_EQUAL(extended_master_secret.data, conn->secrets.version.tls12.master_secret, S2N_TLS_SECRET_LEN);
    };

    /* s2n_prf_calculate_master_secret */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384;

        EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls12.rsa_premaster_secret, premaster_secret_in.data, premaster_secret_in.size);
        EXPECT_MEMCPY_SUCCESS(conn->client_hello.client_random, client_random_in.data, client_random_in.size);
        EXPECT_MEMCPY_SUCCESS(conn->handshake_params.server_random, server_random_in.data, server_random_in.size);

        struct s2n_blob pms = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&pms, conn->secrets.version.tls12.rsa_premaster_secret, sizeof(conn->secrets.version.tls12.rsa_premaster_secret)));

        /* Errors when handshake is not at the Client Key Exchange message */
        EXPECT_FAILURE_WITH_ERRNO(s2n_prf_calculate_master_secret(conn, &pms), S2N_ERR_SAFETY);

        /* Advance handshake to Client Key Exchange message */
        conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
        while (ACTIVE_MESSAGE(conn) != CLIENT_KEY) {
            conn->handshake.message_number++;
        }

        /* Master secret is calculated when handshake is at Client Key Exchange message*/
        EXPECT_SUCCESS(s2n_prf_calculate_master_secret(conn, &pms));
        EXPECT_EQUAL(memcmp(conn->secrets.version.tls12.master_secret, master_secret_in.data, master_secret_in.size), 0);

        /* s2n_prf_calculate_master_secret will produce the same master secret if given the same inputs */
        EXPECT_SUCCESS(s2n_prf_calculate_master_secret(conn, &pms));
        EXPECT_EQUAL(memcmp(conn->secrets.version.tls12.master_secret, master_secret_in.data, master_secret_in.size), 0);

        conn->ems_negotiated = true;
        EXPECT_SUCCESS(s2n_prf_calculate_master_secret(conn, &pms));

        /* Extended master secret calculated is different than the master secret calculated */
        EXPECT_NOT_EQUAL(memcmp(conn->secrets.version.tls12.master_secret, master_secret_in.data, master_secret_in.size), 0);
    };

    /* s2n_prf_get_digest_for_ems calculates the correct digest to generate an extended master secret.
     * Here we test that the retrieved digest is the same as the digest after the Client Key Exchange
     * message is added to the transcript hash.
     *
     *= https://www.rfc-editor.org/rfc/rfc7627#section-3
     *= type=test
     *# When a full TLS handshake takes place, we define
     *#
     *#       session_hash = Hash(handshake_messages)
     *#
     *# where "handshake_messages" refers to all handshake messages sent or
     *# received, starting at the ClientHello up to and including the
     *# ClientKeyExchange message, including the type and length fields of
     *# the handshake messages.
     */
    {
        struct s2n_cert_chain_and_key *tls12_chain_and_key = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&tls12_chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN,
                S2N_DEFAULT_TEST_PRIVATE_KEY));

        struct s2n_config *config = s2n_config_new();
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, tls12_chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20170210"));

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_stuffer client_to_server = { 0 }, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer server_to_client = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_to_server, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_to_client, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));

        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, CLIENT_KEY));

        /* Client writes Client Key Exchange message */
        EXPECT_SUCCESS(s2n_handshake_write_io(client_conn));

        uint8_t data[S2N_MAX_DIGEST_LEN] = { 0 };
        struct s2n_blob digest_for_ems = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&digest_for_ems, data, sizeof(data)));

        /* Get the Client Key transcript */
        EXPECT_SUCCESS(s2n_stuffer_skip_read(&client_to_server, S2N_TLS_RECORD_HEADER_LENGTH));
        uint8_t client_key_message_length = s2n_stuffer_data_available(&client_to_server);
        uint8_t *client_key_message = s2n_stuffer_raw_read(&client_to_server, client_key_message_length);
        struct s2n_blob message = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&message, client_key_message, client_key_message_length));

        s2n_hmac_algorithm prf_alg = server_conn->secure->cipher_suite->prf_alg;
        s2n_hash_algorithm hash_alg = 0;
        POSIX_GUARD(s2n_hmac_hash_alg(prf_alg, &hash_alg));
        EXPECT_OK(s2n_prf_get_digest_for_ems(server_conn, &message, hash_alg, &digest_for_ems));

        /* Server reads Client Key Exchange message */
        EXPECT_SUCCESS(s2n_stuffer_rewind_read(&client_to_server, S2N_TLS_RECORD_HEADER_LENGTH + client_key_message_length));
        EXPECT_SUCCESS(s2n_handshake_read_io(server_conn));

        /* Calculate the digest message after the Server read the Client Key message */
        DEFER_CLEANUP(struct s2n_hash_state current_hash_state = { 0 }, s2n_hash_free);
        uint8_t server_digest[S2N_MAX_DIGEST_LEN] = { 0 };
        uint8_t digest_size = 0;
        EXPECT_SUCCESS(s2n_hash_digest_size(hash_alg, &digest_size));
        EXPECT_SUCCESS(s2n_hash_new(&current_hash_state));
        EXPECT_OK(s2n_handshake_copy_hash_state(server_conn, hash_alg, &current_hash_state));
        EXPECT_SUCCESS(s2n_hash_digest(&current_hash_state, server_digest, digest_size));

        /* Digest for generating the EMS and digest after reading the Client Key message
         * should be the same. */
        EXPECT_BYTEARRAY_EQUAL(server_digest, digest_for_ems.data, digest_size);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls12_chain_and_key));
    }

    /* PRF lifecyle */
    {
        /* Safety */
        {
            EXPECT_ERROR_WITH_ERRNO(s2n_prf_new(NULL), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_prf_wipe(NULL), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_prf_free(NULL), S2N_ERR_NULL);

            struct s2n_connection conn_with_null_prf_space = { 0 };
            EXPECT_NULL(conn_with_null_prf_space.prf_space);

            EXPECT_ERROR_WITH_ERRNO(s2n_prf_wipe(&conn_with_null_prf_space), S2N_ERR_NULL);
            EXPECT_OK(s2n_prf_free(&conn_with_null_prf_space));
        };

        /* Basic lifecyle */
        {
            struct s2n_connection connection = { 0 };
            EXPECT_NULL(connection.prf_space);

            EXPECT_OK(s2n_prf_new(&connection));
            EXPECT_NOT_NULL(connection.prf_space);

            EXPECT_OK(s2n_prf_wipe(&connection));
            EXPECT_NOT_NULL(connection.prf_space);

            EXPECT_OK(s2n_prf_free(&connection));
            EXPECT_NULL(connection.prf_space);
        };

        /* PRF freed by s2n_connection_free_handshake */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_NOT_NULL(conn->prf_space);

            EXPECT_SUCCESS(s2n_connection_free_handshake(conn));
            EXPECT_NULL(conn->prf_space);
        };

        /* Freed PRF restored by s2n_connection_wipe */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_OK(s2n_prf_free(conn));
            EXPECT_NULL(conn->prf_space);

            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            EXPECT_NOT_NULL(conn->prf_space);
        };

        /* PRF usable throughout connection lifecycle */
        {
            struct s2n_blob pms = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&pms, premaster_secret_in.data, premaster_secret_in.size));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls12.rsa_premaster_secret, premaster_secret_in.data, premaster_secret_in.size);
            EXPECT_MEMCPY_SUCCESS(conn->client_hello.client_random, client_random_in.data, client_random_in.size);
            EXPECT_MEMCPY_SUCCESS(conn->handshake_params.server_random, server_random_in.data, server_random_in.size);
            EXPECT_SUCCESS(s2n_prf_tls_master_secret(conn, &pms));
            EXPECT_EQUAL(memcmp(conn->secrets.version.tls12.master_secret, master_secret_in.data, master_secret_in.size), 0);

            EXPECT_SUCCESS(s2n_connection_free_handshake(conn));
            EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls12.rsa_premaster_secret, premaster_secret_in.data, premaster_secret_in.size);
            EXPECT_MEMCPY_SUCCESS(conn->client_hello.client_random, client_random_in.data, client_random_in.size);
            EXPECT_MEMCPY_SUCCESS(conn->handshake_params.server_random, server_random_in.data, server_random_in.size);
            EXPECT_FAILURE_WITH_ERRNO(s2n_prf_tls_master_secret(conn, &pms), S2N_ERR_NULL);

            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls12.rsa_premaster_secret, premaster_secret_in.data, premaster_secret_in.size);
            EXPECT_MEMCPY_SUCCESS(conn->client_hello.client_random, client_random_in.data, client_random_in.size);
            EXPECT_MEMCPY_SUCCESS(conn->handshake_params.server_random, server_random_in.data, server_random_in.size);
            EXPECT_SUCCESS(s2n_prf_tls_master_secret(conn, &pms));
            EXPECT_EQUAL(memcmp(conn->secrets.version.tls12.master_secret, master_secret_in.data, master_secret_in.size), 0);
        };
    };

    END_TEST();
}
