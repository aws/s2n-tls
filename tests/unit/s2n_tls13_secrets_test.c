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
#include "tls/s2n_tls13_secrets.h"

#include <sys/param.h>

#include "crypto/s2n_ecc_evp.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

S2N_RESULT s2n_tls13_extract_secret(struct s2n_connection *conn, s2n_extract_secret_type_t secret_type);
S2N_RESULT s2n_tls13_derive_secret(struct s2n_connection *conn, s2n_extract_secret_type_t secret_type,
        s2n_mode mode, struct s2n_blob *secret);

static S2N_RESULT s2n_set_test_key_shares(struct s2n_connection *conn, const struct s2n_ecc_named_curve *curve)
{
    conn->kex_params.server_ecc_evp_params.negotiated_curve = curve;
    RESULT_GUARD_POSIX(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.server_ecc_evp_params));

    conn->kex_params.client_ecc_evp_params.negotiated_curve = curve;
    RESULT_GUARD_POSIX(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

    return S2N_RESULT_OK;
}

struct s2n_tls13_secrets_test_case {
    s2n_extract_secret_type_t curr_secret_type;
    s2n_extract_secret_type_t next_secret_type;
    s2n_mode secret_mode;
    s2n_mode conn_mode;
    struct s2n_cipher_suite *cipher_suite;
    const struct s2n_ecc_named_curve *curve;
};

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t empty_secret[S2N_TLS13_SECRET_MAX_LEN] = { 0 };

    const struct s2n_cipher_preferences *ciphers = &cipher_preferences_test_all_tls13;
    const struct s2n_ecc_preferences *curves = &s2n_ecc_preferences_test_all;
    const s2n_mode modes[] = { S2N_CLIENT, S2N_SERVER };

    struct s2n_blob test_secret = { 0 };
    uint8_t test_secret_bytes[S2N_TLS13_SECRET_MAX_LEN] = "hello world";
    EXPECT_SUCCESS(s2n_blob_init(&test_secret, test_secret_bytes, sizeof(test_secret_bytes)));

    struct s2n_tls13_secrets_test_case test_cases[1000] = { 0 };
    size_t test_cases_count = 0;
    for (s2n_extract_secret_type_t next_type = S2N_EARLY_SECRET; next_type <= S2N_MASTER_SECRET; next_type++) {
        for (s2n_extract_secret_type_t curr_type = S2N_NONE_SECRET; curr_type <= S2N_MASTER_SECRET; curr_type++) {
            for (size_t cipher_i = 0; cipher_i < ciphers->count; cipher_i++) {
                for (size_t curve_i = 0; curve_i < curves->count; curve_i++) {
                    for (size_t m1_i = 0; m1_i < s2n_array_len(modes); m1_i++) {
                        for (size_t m2_i = 0; m2_i < s2n_array_len(modes); m2_i++) {
                            if (curr_type > next_type) {
                                /* Secret schedule MUST be evaluated in order */
                                continue;
                            }
                            test_cases[test_cases_count] = (struct s2n_tls13_secrets_test_case){
                                .curr_secret_type = curr_type,
                                .next_secret_type = next_type,
                                .secret_mode = modes[m1_i],
                                .conn_mode = modes[m2_i],
                                .cipher_suite = ciphers->suites[cipher_i],
                                .curve = curves->ecc_curves[curve_i],
                            };
                            test_cases_count++;
                        }
                    }
                }
            }
        }
    }
    EXPECT_TRUE(test_cases_count > 0);

    /* Test: s2n_tls13_extract_secret */
    {
        /* Safety */
        {
            struct s2n_connection empty_conn = { 0 };
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);

            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_extract_secret(NULL, S2N_EARLY_SECRET), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_extract_secret(&empty_conn, S2N_EARLY_SECRET), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_extract_secret(conn, -1), S2N_ERR_SAFETY);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_extract_secret(conn, 255), S2N_ERR_SAFETY);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_extract_secret(conn, (S2N_MASTER_SECRET + 1)), S2N_ERR_SAFETY);
        };

        /* No-op if secret already exists */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->secrets.extract_secret_type = S2N_EARLY_SECRET;

            EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_EARLY_SECRET));
            EXPECT_EQUAL(conn->secrets.extract_secret_type, S2N_EARLY_SECRET);
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.extract_secret, empty_secret, sizeof(empty_secret));
        };

        /* Generate all secrets sequentially  */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->secrets.extract_secret_type = S2N_NONE_SECRET;

            EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_EARLY_SECRET));
            EXPECT_EQUAL(conn->secrets.extract_secret_type, S2N_EARLY_SECRET);
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.extract_secret, empty_secret, sizeof(empty_secret));

            EXPECT_OK(s2n_set_test_key_shares(conn, &s2n_ecc_curve_secp256r1));
            EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_HANDSHAKE_SECRET));
            EXPECT_EQUAL(conn->secrets.extract_secret_type, S2N_HANDSHAKE_SECRET);
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.extract_secret, empty_secret, sizeof(empty_secret));

            EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_MASTER_SECRET));
            EXPECT_EQUAL(conn->secrets.extract_secret_type, S2N_MASTER_SECRET);
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.extract_secret, empty_secret, sizeof(empty_secret));
        };

        /* Generate all secrets at once (backfill) */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->secrets.extract_secret_type = S2N_NONE_SECRET;
            EXPECT_OK(s2n_set_test_key_shares(conn, &s2n_ecc_curve_secp256r1));

            EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_MASTER_SECRET));
            EXPECT_EQUAL(conn->secrets.extract_secret_type, S2N_MASTER_SECRET);
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.extract_secret, empty_secret, sizeof(empty_secret));
        }

        /* All valid parameter combinations should succeed */
        for (size_t i = 0; i < test_cases_count; i++) {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(test_cases[i].conn_mode),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = test_cases[i].cipher_suite;
            conn->secrets.extract_secret_type = test_cases[i].curr_secret_type;
            EXPECT_OK(s2n_set_test_key_shares(conn, test_cases[i].curve));
            EXPECT_OK(s2n_tls13_extract_secret(conn, test_cases[i].next_secret_type));
        }
    };

    /* Test: s2n_tls13_derive_secret */
    {
        const uint32_t handshake_type = NEGOTIATED | FULL_HANDSHAKE;
        const int message_nums[] = {
            [S2N_EARLY_SECRET] = 0,
            [S2N_HANDSHAKE_SECRET] = 1,
            [S2N_MASTER_SECRET] = 5,
        };

        /* Safety */
        {
            struct s2n_blob blob = { 0 };
            struct s2n_connection empty_conn = { 0 };
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);

            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_derive_secret(NULL, S2N_EARLY_SECRET, S2N_CLIENT, &blob), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_derive_secret(&empty_conn, S2N_EARLY_SECRET, S2N_CLIENT, &blob), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_derive_secret(conn, -1, S2N_CLIENT, &blob), S2N_ERR_SAFETY);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_derive_secret(conn, 255, S2N_CLIENT, &blob), S2N_ERR_SAFETY);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_derive_secret(conn, S2N_EARLY_SECRET, S2N_CLIENT, NULL), S2N_ERR_NULL);
        };

        /* Generates a secret */
        {
            uint8_t output_bytes[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
            struct s2n_blob output = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&output, output_bytes, sizeof(output_bytes)));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->secrets.extract_secret_type = S2N_NONE_SECRET;

            EXPECT_OK(s2n_tls13_derive_secret(conn, S2N_EARLY_SECRET, S2N_SERVER, &output));
            EXPECT_BYTEARRAY_NOT_EQUAL(output.data, empty_secret, sizeof(empty_secret));
        };

        /* Fails if correct transcript digest not available */
        {
            uint8_t output_bytes[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
            struct s2n_blob output = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&output, output_bytes, sizeof(output_bytes)));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->handshake.handshake_type = handshake_type;
            EXPECT_OK(s2n_set_test_key_shares(conn, &s2n_ecc_curve_secp256r1));

            /* Fails with incorrect transcript */
            conn->handshake.message_number = message_nums[S2N_HANDSHAKE_SECRET];
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_derive_secret(conn, S2N_MASTER_SECRET, S2N_SERVER, &output),
                    S2N_ERR_SECRET_SCHEDULE_STATE);

            /* Succeeds with correct transcript */
            conn->handshake.message_number = message_nums[S2N_MASTER_SECRET];
            EXPECT_OK(s2n_tls13_derive_secret(conn, S2N_MASTER_SECRET, S2N_SERVER, &output));
        };

        /* Calculates previous extract secrets if necessary */
        {
            uint8_t output_bytes[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
            struct s2n_blob output = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&output, output_bytes, sizeof(output_bytes)));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
            conn->actual_protocol_version = S2N_TLS13;
            conn->handshake.handshake_type = handshake_type;
            conn->handshake.message_number = message_nums[S2N_HANDSHAKE_SECRET];
            EXPECT_OK(s2n_set_test_key_shares(conn, &s2n_ecc_curve_secp256r1));

            conn->secrets.extract_secret_type = S2N_NONE_SECRET;
            EXPECT_OK(s2n_tls13_derive_secret(conn, S2N_HANDSHAKE_SECRET, S2N_SERVER, &output));
            EXPECT_EQUAL(conn->secrets.extract_secret_type, S2N_HANDSHAKE_SECRET);
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.extract_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(output.data, empty_secret, sizeof(empty_secret));
        };

        /* All valid parameter combinations should succeed */
        for (size_t i = 0; i < test_cases_count; i++) {
            uint8_t output_bytes[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
            struct s2n_blob output = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&output, output_bytes, sizeof(output_bytes)));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(test_cases[i].conn_mode),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = test_cases[i].cipher_suite;
            conn->secrets.extract_secret_type = test_cases[i].curr_secret_type;
            EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
            conn->actual_protocol_version = S2N_TLS13;
            conn->handshake.handshake_type = handshake_type;
            conn->handshake.message_number = message_nums[test_cases[i].next_secret_type];
            EXPECT_OK(s2n_set_test_key_shares(conn, test_cases[i].curve));
            EXPECT_OK(s2n_tls13_derive_secret(conn, test_cases[i].next_secret_type, test_cases[i].secret_mode, &output));
            EXPECT_BYTEARRAY_NOT_EQUAL(output.data, empty_secret, sizeof(empty_secret));
        }
    };

    /* s2n_tls13_secrets_clean */
    {
        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_tls13_secrets_clean(NULL), S2N_ERR_NULL);

        /* Wipes all secrets */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->actual_protocol_version = S2N_TLS13;

            EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls13.extract_secret, test_secret.data, test_secret.size);
            EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls13.client_early_secret, test_secret.data, test_secret.size);
            EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls13.client_handshake_secret, test_secret.data, test_secret.size);
            EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls13.server_handshake_secret, test_secret.data, test_secret.size);
            EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls13.client_app_secret, test_secret.data, test_secret.size);
            EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls13.server_app_secret, test_secret.data, test_secret.size);
            EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls13.exporter_master_secret, test_secret.data, test_secret.size);
            EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls13.resumption_master_secret, test_secret.data, test_secret.size);

            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.extract_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.client_early_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.client_handshake_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.server_handshake_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.client_app_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.server_app_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.exporter_master_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.resumption_master_secret, empty_secret, sizeof(empty_secret));

            EXPECT_OK(s2n_tls13_secrets_clean(conn));

            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.extract_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.client_early_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.client_handshake_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.server_handshake_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.client_app_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.server_app_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.exporter_master_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.resumption_master_secret, empty_secret, sizeof(empty_secret));
        };
    };

    /* Test s2n_tls13_secrets_get */
    {
        /* Safety */
        {
            struct s2n_blob result = { 0 };
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_secrets_get(NULL, S2N_HANDSHAKE_SECRET, S2N_CLIENT, &result), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_secrets_get(conn, S2N_HANDSHAKE_SECRET, S2N_CLIENT, NULL), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_secrets_get(conn, S2N_NONE_SECRET, S2N_CLIENT, &result), S2N_ERR_SAFETY);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_secrets_get(conn, -1, S2N_CLIENT, &result), S2N_ERR_SAFETY);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_secrets_get(conn, 100, S2N_CLIENT, &result), S2N_ERR_SAFETY);
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_secrets_get(conn, S2N_EARLY_SECRET, S2N_SERVER, &result), S2N_ERR_SAFETY);

            conn->secrets.extract_secret_type = S2N_NONE_SECRET;
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_secrets_get(conn, S2N_HANDSHAKE_SECRET, S2N_CLIENT, &result), S2N_ERR_SAFETY);

            struct s2n_crypto_parameters *secure = conn->secure;
            conn->secure = NULL;
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_secrets_get(conn, S2N_HANDSHAKE_SECRET, S2N_CLIENT, &result), S2N_ERR_NULL);
            conn->secure = secure;

            struct s2n_cipher_suite *cipher_suite = conn->secure->cipher_suite;
            conn->secure->cipher_suite = NULL;
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_secrets_get(conn, S2N_HANDSHAKE_SECRET, S2N_CLIENT, &result), S2N_ERR_NULL);
            conn->secure->cipher_suite = cipher_suite;
        };

        /* Retrieves a secret */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->actual_protocol_version = S2N_TLS13;

            EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls13.client_handshake_secret,
                    test_secret.data, test_secret.size);
            conn->secrets.extract_secret_type = S2N_HANDSHAKE_SECRET;

            struct s2n_blob result = { 0 };
            uint8_t result_bytes[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&result, result_bytes, sizeof(result_bytes)));
            EXPECT_OK(s2n_tls13_secrets_get(conn, S2N_HANDSHAKE_SECRET, S2N_CLIENT, &result));

            EXPECT_TRUE(result.size > 0);
            EXPECT_TRUE(result.size <= S2N_TLS13_SECRET_MAX_LEN);
            EXPECT_BYTEARRAY_EQUAL(result.data, test_secret.data, result.size);
        };
    };

    /* s2n_tls13_secrets_update */
    {
        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_tls13_secrets_update(NULL), S2N_ERR_NULL);

        /* Derives early secret on CLIENT_HELLO */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.client_early_secret,
                    empty_secret, sizeof(empty_secret));

            /* Early secret not derived if early data not requested */
            conn->early_data_state = S2N_EARLY_DATA_NOT_REQUESTED;
            EXPECT_OK(s2n_tls13_secrets_update(conn));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.client_early_secret,
                    empty_secret, sizeof(empty_secret));

            /* Early secret not derived if early data rejected */
            conn->early_data_state = S2N_EARLY_DATA_REJECTED;
            EXPECT_OK(s2n_tls13_secrets_update(conn));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.client_early_secret,
                    empty_secret, sizeof(empty_secret));

            /* Early secret derived if early data requested */
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_OK(s2n_tls13_secrets_update(conn));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.client_early_secret,
                    empty_secret, sizeof(empty_secret));

            /* Clear secret */
            EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls13.client_early_secret,
                    empty_secret, sizeof(empty_secret));

            /* Early secret derived if early data accepted */
            conn->early_data_state = S2N_EARLY_DATA_ACCEPTED;
            EXPECT_OK(s2n_tls13_secrets_update(conn));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.client_early_secret,
                    empty_secret, sizeof(empty_secret));
        };

        /* Derives handshake secrets on SERVER_HELLO */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_connection_set_test_handshake_secret(conn, &test_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.client_handshake_secret,
                    empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.server_handshake_secret,
                    empty_secret, sizeof(empty_secret));

            while (s2n_conn_get_current_message_type(conn) != SERVER_HELLO) {
                conn->handshake.message_number++;
            }
            EXPECT_OK(s2n_tls13_secrets_update(conn));

            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.client_handshake_secret,
                    empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.server_handshake_secret,
                    empty_secret, sizeof(empty_secret));
        };

        /* Computes finished keys on SERVER_HELLO */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_connection_set_test_handshake_secret(conn, &test_secret));
            EXPECT_EQUAL(conn->handshake.finished_len, 0);
            EXPECT_BYTEARRAY_EQUAL(conn->handshake.client_finished,
                    empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->handshake.server_finished,
                    empty_secret, sizeof(empty_secret));

            while (s2n_conn_get_current_message_type(conn) != SERVER_HELLO) {
                conn->handshake.message_number++;
            }
            EXPECT_OK(s2n_tls13_secrets_update(conn));

            uint8_t expected_len = 0;
            EXPECT_SUCCESS(s2n_hmac_digest_size(conn->secure->cipher_suite->prf_alg, &expected_len));
            EXPECT_EQUAL(conn->handshake.finished_len, expected_len);
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->handshake.client_finished,
                    empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->handshake.server_finished,
                    empty_secret, sizeof(empty_secret));
        };

        /* Derives application secrets on SERVER_FINISHED */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_connection_set_test_master_secret(conn, &test_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.client_app_secret,
                    empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.server_app_secret,
                    empty_secret, sizeof(empty_secret));

            while (s2n_conn_get_current_message_type(conn) != SERVER_FINISHED) {
                conn->handshake.message_number++;
            }
            EXPECT_OK(s2n_tls13_secrets_update(conn));

            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.client_app_secret,
                    empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.server_app_secret,
                    empty_secret, sizeof(empty_secret));
        };

        /* Derives resumption secret on CLIENT_FINISHED */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_connection_set_test_master_secret(conn, &test_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.resumption_master_secret,
                    empty_secret, sizeof(empty_secret));

            while (s2n_conn_get_current_message_type(conn) != CLIENT_FINISHED) {
                conn->handshake.message_number++;
            }
            EXPECT_OK(s2n_tls13_secrets_update(conn));

            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.resumption_master_secret,
                    empty_secret, sizeof(empty_secret));
        };
    };

    /* s2n_connection_export_secret */
    {
        /* Derives exporter secret on SERVER_FINISHED */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_connection_set_test_master_secret(conn, &test_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.version.tls13.exporter_master_secret,
                    empty_secret, sizeof(empty_secret));

            while (s2n_conn_get_current_message_type(conn) != SERVER_FINISHED) {
                conn->handshake.message_number++;
            }
            EXPECT_OK(s2n_tls13_secrets_update(conn));

            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.version.tls13.exporter_master_secret,
                    empty_secret, sizeof(empty_secret));

            /*
             * s2n_connection_tls_exporter requires us to finish the handshake.
             * The above is needed since s2n_tls13_secrets_update will only
             * initialize when it sees the SERVER_FINISHED frame.
             */
            EXPECT_OK(s2n_skip_handshake(conn));

            uint8_t output[32] = { 0 };
            int result = s2n_connection_tls_exporter(
                    conn,
                    (const uint8_t *) "label",
                    sizeof("label") - 1,
                    (const uint8_t *) "context",
                    sizeof("context") - 1,
                    output,
                    sizeof(output));
            EXPECT_SUCCESS(result);
            /*
             * If updating this value, it's a good idea to make sure the update
             * matches OpenSSL's SSL_export_keying_material. The easiest known
             * way of doing that is building a simple client/server pair and
             * calling the s2n and OpenSSL APIs after a handshake on both
             * sides; you should get identical results with identical
             * label/context parameters. This particular value though is not
             * checked as its dependent on the s2n-specific test master secret.
             */
            S2N_BLOB_FROM_HEX(expected, "3a 72 eb 08 10 a3 69 f3 06 f2 77 11 70 ad d5 76 bd 21 15 \
                    46 d4 c8 fb 80 1a 93 04 1e ac 59 aa 47");
            EXPECT_EQUAL(sizeof(output), expected.size);
            EXPECT_BYTEARRAY_EQUAL(output, expected.data, expected.size);
        };
    };

    END_TEST();
}
