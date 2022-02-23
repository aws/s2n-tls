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

#include <sys/param.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#include "tls/s2n_tls13_secrets.h"

#include "crypto/s2n_ecc_evp.h"

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

    struct s2n_tls13_secrets_test_case test_cases[1000] = { 0 };
    size_t test_cases_count = 0;
    for (s2n_extract_secret_type_t next_type = S2N_EARLY_SECRET; next_type <= S2N_MASTER_SECRET; next_type++) {
        for (s2n_extract_secret_type_t curr_type = S2N_NONE_SECRET; curr_type <= S2N_MASTER_SECRET; curr_type++) {
            for (size_t cipher_i = 0; cipher_i < ciphers->count; cipher_i++) {
                for (size_t curve_i = 0; curve_i < curves->count; curve_i++) {
                    for (size_t m1_i = 0; m1_i < s2n_array_len(modes); m1_i++) {
                        for (size_t m2_i = 0; m2_i < s2n_array_len(modes); m2_i++) {
                            test_cases[test_cases_count] = (struct s2n_tls13_secrets_test_case) {
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
        }

        /* No-op if secret already exists */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->secrets.tls13.secrets_state = S2N_EARLY_SECRET;

            EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_EARLY_SECRET));
            EXPECT_EQUAL(conn->secrets.tls13.secrets_state, S2N_EARLY_SECRET);
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.tls13.early_secret, empty_secret, sizeof(empty_secret));
        }

        /* Generate all secrets sequentially  */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->secrets.tls13.secrets_state = S2N_NONE_SECRET;

            EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_EARLY_SECRET));
            EXPECT_EQUAL(conn->secrets.tls13.secrets_state, S2N_EARLY_SECRET);
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.tls13.early_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.tls13.handshake_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.tls13.master_secret, empty_secret, sizeof(empty_secret));

            EXPECT_OK(s2n_set_test_key_shares(conn, &s2n_ecc_curve_secp256r1));
            EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_HANDSHAKE_SECRET));
            EXPECT_EQUAL(conn->secrets.tls13.secrets_state, S2N_HANDSHAKE_SECRET);
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.tls13.early_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.tls13.handshake_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.tls13.master_secret, empty_secret, sizeof(empty_secret));

            EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_MASTER_SECRET));
            EXPECT_EQUAL(conn->secrets.tls13.secrets_state, S2N_MASTER_SECRET);
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.tls13.early_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.tls13.handshake_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.tls13.master_secret, empty_secret, sizeof(empty_secret));
        }

        /* Generate all secrets at once (backfill) */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->secrets.tls13.secrets_state = S2N_NONE_SECRET;
            EXPECT_OK(s2n_set_test_key_shares(conn, &s2n_ecc_curve_secp256r1));

            EXPECT_OK(s2n_tls13_extract_secret(conn, S2N_MASTER_SECRET));
            EXPECT_EQUAL(conn->secrets.tls13.secrets_state, S2N_MASTER_SECRET);
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.tls13.early_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.tls13.handshake_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.tls13.master_secret, empty_secret, sizeof(empty_secret));
        }

        /* All valid parameter combinations should succeed */
        for (size_t i = 0; i < test_cases_count; i ++) {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(test_cases[i].conn_mode),
                    s2n_connection_ptr_free);
            conn->secure.cipher_suite = test_cases[i].cipher_suite;
            conn->secrets.tls13.secrets_state = test_cases[i].curr_secret_type;
            EXPECT_OK(s2n_set_test_key_shares(conn, test_cases[i].curve));
            EXPECT_OK(s2n_tls13_extract_secret(conn, test_cases[i].next_secret_type));
        }
    }

    /* Test: s2n_tls13_derive_secret */
    {
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
        }

        /* Generates a secret */
        {
            uint8_t output_bytes[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
            struct s2n_blob output = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&output, output_bytes, sizeof(output_bytes)));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->secrets.tls13.secrets_state = S2N_NONE_SECRET;

            EXPECT_OK(s2n_tls13_derive_secret(conn, S2N_EARLY_SECRET, S2N_SERVER, &output));
            EXPECT_BYTEARRAY_NOT_EQUAL(output.data, empty_secret, sizeof(empty_secret));
        }

        /* Extracts the parent secret if necessary */
        {
            uint8_t output_bytes[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
            struct s2n_blob output = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&output, output_bytes, sizeof(output_bytes)));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->secrets.tls13.secrets_state = S2N_NONE_SECRET;
            EXPECT_OK(s2n_set_test_key_shares(conn, &s2n_ecc_curve_secp256r1));

            EXPECT_OK(s2n_tls13_derive_secret(conn, S2N_HANDSHAKE_SECRET, S2N_SERVER, &output));
            EXPECT_EQUAL(conn->secrets.tls13.secrets_state, S2N_HANDSHAKE_SECRET);
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.tls13.early_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secrets.tls13.handshake_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->secrets.tls13.master_secret, empty_secret, sizeof(empty_secret));
            EXPECT_BYTEARRAY_NOT_EQUAL(output.data, empty_secret, sizeof(empty_secret));
        }

        /* All valid parameter combinations should succeed */
        for (size_t i = 0; i < test_cases_count; i ++) {
            uint8_t output_bytes[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
            struct s2n_blob output = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&output, output_bytes, sizeof(output_bytes)));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(test_cases[i].conn_mode),
                    s2n_connection_ptr_free);
            conn->secure.cipher_suite = test_cases[i].cipher_suite;
            conn->secrets.tls13.secrets_state = test_cases[i].curr_secret_type;
            EXPECT_OK(s2n_set_test_key_shares(conn, test_cases[i].curve));
            EXPECT_OK(s2n_tls13_derive_secret(conn, test_cases[i].next_secret_type, test_cases[i].secret_mode, &output));
            EXPECT_BYTEARRAY_NOT_EQUAL(output.data, empty_secret, sizeof(empty_secret));
        }
    }

    END_TEST();
}
