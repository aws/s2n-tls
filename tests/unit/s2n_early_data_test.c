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

#include "tls/s2n_early_data.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#define TEST_SIZE 10

typedef struct {
    const s2n_early_data_state *states;
    size_t len;
} s2n_early_state_sequence;

/* We want to verify that applying s2n_connection_set_early_data_state to the current state
 * can only produce valid state sequences.
 *
 * We check every possible next state and verify that the only transitions that
 * s2n_connection_set_early_data_state allows are those in the valid state sequences. Then, for
 * every valid transition, we call this method again recursively. The recursion ends when we either
 * reach the end of a valid state sequence or encounter an invalid state sequence.
 */
static S2N_RESULT s2n_test_all_early_data_sequences(struct s2n_connection *conn, size_t i,
        const s2n_early_state_sequence *valid_early_state_sequences, size_t valid_early_state_sequences_len)
{
    s2n_early_data_state current_state = conn->early_data_state;
    for (s2n_early_data_state next_state = 0; next_state < S2N_EARLY_DATA_STATES_COUNT; next_state++) {
        /* We always allow no-op transitions, so ignore them */
        if (next_state == current_state) {
            continue;
        }

        conn->early_data_state = current_state;

        bool actual_valid = s2n_result_is_ok(s2n_connection_set_early_data_state(conn, next_state));
        bool expected_valid = false;

        size_t next_i = i + 1;
        for (size_t j = 0; j < valid_early_state_sequences_len; j++) {
            if (next_i < valid_early_state_sequences[j].len) {
                expected_valid |= (valid_early_state_sequences[j].states[i] == current_state)
                        && (valid_early_state_sequences[j].states[next_i] == next_state);
            }
        }

        RESULT_ENSURE_EQ(actual_valid, expected_valid);

        if (expected_valid) {
            RESULT_GUARD(s2n_test_all_early_data_sequences(conn, i + 1,
                    valid_early_state_sequences, valid_early_state_sequences_len));
        }
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_alloc_test_config_buffers(struct s2n_early_data_config *config)
{
    RESULT_GUARD_POSIX(s2n_alloc(&config->application_protocol, TEST_SIZE));
    RESULT_ENSURE_NE(config->application_protocol.size, 0);
    RESULT_GUARD_POSIX(s2n_alloc(&config->context, TEST_SIZE));
    RESULT_ENSURE_NE(config->context.size, 0);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_config_buffers_freed(struct s2n_early_data_config *config)
{
    RESULT_ENSURE_EQ(config->application_protocol.data, NULL);
    RESULT_ENSURE_EQ(config->application_protocol.size, 0);
    RESULT_ENSURE_EQ(config->context.data, NULL);
    RESULT_ENSURE_EQ(config->context.size, 0);
    return S2N_RESULT_OK;
}

static int s2n_test_early_data_cb(struct s2n_connection *conn, struct s2n_offered_early_data *early_data)
{
    POSIX_ENSURE_REF(conn);

    uint16_t context_len = 0;
    POSIX_GUARD(s2n_offered_early_data_get_context_length(early_data, &context_len));
    POSIX_ENSURE_EQ(context_len, 1);

    uint8_t context = 0;
    POSIX_GUARD(s2n_offered_early_data_get_context(early_data, &context, 1));

    if (context) {
        POSIX_GUARD(s2n_offered_early_data_accept(early_data));
    } else {
        POSIX_GUARD(s2n_offered_early_data_reject(early_data));
    }
    return S2N_SUCCESS;
}

struct s2n_offered_early_data *async_early_data = NULL;
static int s2n_test_async_early_data_cb(struct s2n_connection *conn, struct s2n_offered_early_data *early_data)
{
    POSIX_ENSURE_REF(conn);
    async_early_data = early_data;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    const uint8_t test_value[] = "test value";
    const uint8_t test_value_2[] = "more test data";

    const uint32_t nonzero_max_early_data = 10;

    /* Test s2n_connection_set_early_data_state */
    {
        /* Safety check */
        EXPECT_ERROR_WITH_ERRNO(s2n_connection_set_early_data_state(NULL, 0), S2N_ERR_NULL);

        const s2n_early_data_state early_data_not_requested_seq[] = {
            S2N_UNKNOWN_EARLY_DATA_STATE, S2N_EARLY_DATA_NOT_REQUESTED
        };
        const s2n_early_data_state early_data_rejected_seq[] = {
            S2N_UNKNOWN_EARLY_DATA_STATE, S2N_EARLY_DATA_REQUESTED, S2N_EARLY_DATA_REJECTED
        };
        const s2n_early_data_state early_data_success_seq[] = {
            S2N_UNKNOWN_EARLY_DATA_STATE, S2N_EARLY_DATA_REQUESTED, S2N_EARLY_DATA_ACCEPTED, S2N_END_OF_EARLY_DATA
        };

        /* Test known valid / invalid transitions */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);

            conn->early_data_state = 0;
            EXPECT_OK(s2n_connection_set_early_data_state(conn, S2N_UNKNOWN_EARLY_DATA_STATE));

            conn->early_data_state = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_connection_set_early_data_state(conn, S2N_EARLY_DATA_STATES_COUNT),
                    S2N_ERR_INVALID_EARLY_DATA_STATE);

            conn->early_data_state = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_connection_set_early_data_state(conn, S2N_EARLY_DATA_STATES_COUNT + 1),
                    S2N_ERR_INVALID_EARLY_DATA_STATE);

            conn->early_data_state = 0;
            EXPECT_OK(s2n_connection_set_early_data_state(conn, S2N_EARLY_DATA_REQUESTED));

            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_OK(s2n_connection_set_early_data_state(conn, S2N_EARLY_DATA_REJECTED));

            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_ERROR_WITH_ERRNO(s2n_connection_set_early_data_state(conn, S2N_END_OF_EARLY_DATA),
                    S2N_ERR_INVALID_EARLY_DATA_STATE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test that only the expected sequences of states are possible.
         * Given every possible sequence of early data states, test that s2n_connection_set_early_data_state
         * can only be used to iterate through the known valid sequences. */
        {
            /* Test with the correct expected sequences */
            {
                const s2n_early_state_sequence valid_early_state_sequences[] = {
                    { .states = early_data_not_requested_seq, .len = s2n_array_len(early_data_not_requested_seq) },
                    { .states = early_data_rejected_seq, .len = s2n_array_len(early_data_rejected_seq) },
                    { .states = early_data_success_seq, .len = s2n_array_len(early_data_success_seq) },
                };

                struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
                EXPECT_NOT_NULL(conn);
                EXPECT_OK(s2n_test_all_early_data_sequences(conn, 0,
                        valid_early_state_sequences, s2n_array_len(valid_early_state_sequences)));
                EXPECT_SUCCESS(s2n_connection_free(conn));
            };

            /* Sanity check: adding an invalid expected sequence causes test to fail */
            {
                const s2n_early_data_state invalid_seq[] = {
                    S2N_UNKNOWN_EARLY_DATA_STATE, S2N_EARLY_DATA_ACCEPTED, S2N_END_OF_EARLY_DATA
                };
                const s2n_early_state_sequence test_early_state_sequences[] = {
                    { .states = early_data_not_requested_seq, .len = s2n_array_len(early_data_not_requested_seq) },
                    { .states = early_data_rejected_seq, .len = s2n_array_len(early_data_rejected_seq) },
                    { .states = early_data_success_seq, .len = s2n_array_len(early_data_success_seq) },
                    { .states = invalid_seq, .len = s2n_array_len(invalid_seq) },
                };

                struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
                EXPECT_NOT_NULL(conn);
                EXPECT_ERROR(s2n_test_all_early_data_sequences(conn, 0,
                        test_early_state_sequences, s2n_array_len(test_early_state_sequences)));
                EXPECT_SUCCESS(s2n_connection_free(conn));
            };

            /* Sanity check: removing one of the expected sequences causes test to fail */
            {
                const s2n_early_state_sequence test_early_state_sequences[] = {
                    { .states = early_data_not_requested_seq, .len = s2n_array_len(early_data_not_requested_seq) },
                    { .states = early_data_success_seq, .len = s2n_array_len(early_data_success_seq) },
                };

                struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
                EXPECT_NOT_NULL(conn);
                EXPECT_ERROR(s2n_test_all_early_data_sequences(conn, 0,
                        test_early_state_sequences, s2n_array_len(test_early_state_sequences)));
                EXPECT_SUCCESS(s2n_connection_free(conn));
            };
        };
    };

    /* Test s2n_early_data_config_free */
    {
        /* Safety check */
        EXPECT_OK(s2n_early_data_config_free(NULL));

        /* Resets everything */
        {
            struct s2n_early_data_config config = { 0 };
            EXPECT_OK(s2n_alloc_test_config_buffers(&config));

            EXPECT_OK(s2n_early_data_config_free(&config));
            EXPECT_OK(s2n_test_config_buffers_freed(&config));
        };

        /* Called by s2n_psk_wipe */
        {
            struct s2n_psk psk = { 0 };
            EXPECT_OK(s2n_alloc_test_config_buffers(&psk.early_data_config));

            EXPECT_OK(s2n_psk_wipe(&psk));
            EXPECT_OK(s2n_test_config_buffers_freed(&psk.early_data_config));
        };

        /* Called by s2n_psk_free */
        {
            struct s2n_psk *psk = s2n_external_psk_new();
            EXPECT_OK(s2n_alloc_test_config_buffers(&psk->early_data_config));

            EXPECT_SUCCESS(s2n_psk_free(&psk));
            /* A memory leak in this test would indicate that s2n_psk_free isn't freeing the buffers. */
        };
    };

    /* Test s2n_psk_configure_early_data */
    {
        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_psk_configure_early_data(NULL, nonzero_max_early_data, 1, 1), S2N_ERR_NULL);

        /* Set valid configuration */
        {
            uint32_t expected_max_early_data_size = 1000;
            const struct s2n_cipher_suite *expected_cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            DEFER_CLEANUP(struct s2n_psk *psk = s2n_external_psk_new(), s2n_psk_free);
            EXPECT_SUCCESS(s2n_psk_configure_early_data(psk, expected_max_early_data_size,
                    expected_cipher_suite->iana_value[0], expected_cipher_suite->iana_value[1]));

            EXPECT_EQUAL(psk->early_data_config.max_early_data_size, expected_max_early_data_size);
            EXPECT_EQUAL(psk->early_data_config.protocol_version, S2N_TLS13);
            EXPECT_EQUAL(psk->early_data_config.cipher_suite, expected_cipher_suite);
        };

        /* Set cipher suite must match hmac algorithm */
        {
            DEFER_CLEANUP(struct s2n_psk *psk = s2n_external_psk_new(), s2n_psk_free);
            const struct s2n_cipher_suite *cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

            psk->hmac_alg = cipher_suite->prf_alg + 1;
            EXPECT_FAILURE_WITH_ERRNO(s2n_psk_configure_early_data(psk, nonzero_max_early_data,
                                              cipher_suite->iana_value[0], cipher_suite->iana_value[1]),
                    S2N_ERR_INVALID_ARGUMENT);

            psk->hmac_alg = cipher_suite->prf_alg;
            EXPECT_SUCCESS(s2n_psk_configure_early_data(psk, nonzero_max_early_data,
                    cipher_suite->iana_value[0], cipher_suite->iana_value[1]));
            EXPECT_EQUAL(psk->early_data_config.cipher_suite, cipher_suite);
        };
    };

    /* Test s2n_psk_set_application_protocol */
    {
        /* Safety checks */
        {
            struct s2n_psk psk = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_application_protocol(&psk, NULL, 1), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_application_protocol(NULL, test_value, 1), S2N_ERR_NULL);
        };

        DEFER_CLEANUP(struct s2n_psk *psk = s2n_external_psk_new(), s2n_psk_free);
        EXPECT_EQUAL(psk->early_data_config.application_protocol.size, 0);
        EXPECT_EQUAL(psk->early_data_config.application_protocol.allocated, 0);

        /* Set empty value as no-op */
        EXPECT_SUCCESS(s2n_psk_set_application_protocol(psk, test_value, 0));
        EXPECT_EQUAL(psk->early_data_config.application_protocol.size, 0);
        EXPECT_EQUAL(psk->early_data_config.application_protocol.allocated, 0);

        /* Set valid value */
        EXPECT_SUCCESS(s2n_psk_set_application_protocol(psk, test_value, sizeof(test_value)));
        EXPECT_EQUAL(psk->early_data_config.application_protocol.size, sizeof(test_value));
        EXPECT_BYTEARRAY_EQUAL(psk->early_data_config.application_protocol.data, test_value, sizeof(test_value));

        /* Replace previous value */
        EXPECT_SUCCESS(s2n_psk_set_application_protocol(psk, test_value_2, sizeof(test_value_2)));
        EXPECT_EQUAL(psk->early_data_config.application_protocol.size, sizeof(test_value_2));
        EXPECT_BYTEARRAY_EQUAL(psk->early_data_config.application_protocol.data, test_value_2, sizeof(test_value_2));

        /* Clear with empty value */
        EXPECT_SUCCESS(s2n_psk_set_application_protocol(psk, test_value, 0));
        EXPECT_EQUAL(psk->early_data_config.application_protocol.size, 0);
        EXPECT_EQUAL(psk->early_data_config.application_protocol.allocated, 0);

        /* Repeat clear */
        EXPECT_SUCCESS(s2n_psk_set_application_protocol(psk, test_value, 0));
        EXPECT_EQUAL(psk->early_data_config.application_protocol.size, 0);
        EXPECT_EQUAL(psk->early_data_config.application_protocol.allocated, 0);
    };

    /* Test s2n_psk_set_early_data_context */
    {
        /* Safety checks */
        {
            struct s2n_psk psk = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_early_data_context(&psk, NULL, 1), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_early_data_context(NULL, test_value, 1), S2N_ERR_NULL);
        };

        DEFER_CLEANUP(struct s2n_psk *psk = s2n_external_psk_new(), s2n_psk_free);
        EXPECT_EQUAL(psk->early_data_config.context.size, 0);
        EXPECT_EQUAL(psk->early_data_config.context.allocated, 0);

        /* Set empty value as no-op */
        EXPECT_SUCCESS(s2n_psk_set_early_data_context(psk, test_value, 0));
        EXPECT_EQUAL(psk->early_data_config.context.size, 0);
        EXPECT_EQUAL(psk->early_data_config.context.allocated, 0);

        /* Set valid value */
        EXPECT_SUCCESS(s2n_psk_set_early_data_context(psk, test_value, sizeof(test_value)));
        EXPECT_EQUAL(psk->early_data_config.context.size, sizeof(test_value));
        EXPECT_BYTEARRAY_EQUAL(psk->early_data_config.context.data, test_value, sizeof(test_value));

        /* Replace previous value */
        EXPECT_SUCCESS(s2n_psk_set_early_data_context(psk, test_value_2, sizeof(test_value_2)));
        EXPECT_EQUAL(psk->early_data_config.context.size, sizeof(test_value_2));
        EXPECT_BYTEARRAY_EQUAL(psk->early_data_config.context.data, test_value_2, sizeof(test_value_2));

        /* Clear with empty value */
        EXPECT_SUCCESS(s2n_psk_set_early_data_context(psk, test_value, 0));
        EXPECT_EQUAL(psk->early_data_config.context.size, 0);
        EXPECT_EQUAL(psk->early_data_config.context.allocated, 0);

        /* Repeat clear */
        EXPECT_SUCCESS(s2n_psk_set_early_data_context(psk, test_value, 0));
        EXPECT_EQUAL(psk->early_data_config.context.size, 0);
        EXPECT_EQUAL(psk->early_data_config.context.allocated, 0);
    };

    /* Test s2n_early_data_config_clone */
    {
        const uint8_t test_bad_value[] = "wrong";
        const uint8_t test_apln[] = "protocol";
        const uint8_t test_context[] = "context";
        const uint8_t test_version = UINT8_MAX;
        const uint32_t test_max_early_data = 10;
        const struct s2n_cipher_suite *test_cipher_suite = &s2n_tls13_chacha20_poly1305_sha256;

        for (size_t called_directly = 0; called_directly < 2; called_directly++) {
            struct s2n_psk *original = s2n_external_psk_new();
            EXPECT_NOT_NULL(original);
            EXPECT_SUCCESS(s2n_psk_configure_early_data(original, test_max_early_data,
                    test_cipher_suite->iana_value[0], test_cipher_suite->iana_value[1]));
            EXPECT_SUCCESS(s2n_psk_set_application_protocol(original, test_apln, sizeof(test_apln)));
            EXPECT_SUCCESS(s2n_psk_set_early_data_context(original, test_context, sizeof(test_context)));
            original->early_data_config.protocol_version = test_version;

            DEFER_CLEANUP(struct s2n_psk *clone = s2n_external_psk_new(), s2n_psk_free);
            EXPECT_SUCCESS(s2n_psk_set_application_protocol(clone, test_bad_value, sizeof(test_bad_value)));
            EXPECT_NOT_NULL(clone);

            if (called_directly) {
                EXPECT_OK(s2n_early_data_config_clone(clone, &original->early_data_config));
            } else {
                EXPECT_SUCCESS(s2n_psk_set_identity(original, test_bad_value, sizeof(test_bad_value)));
                EXPECT_SUCCESS(s2n_psk_set_secret(original, test_bad_value, sizeof(test_bad_value)));
                EXPECT_OK(s2n_psk_clone(clone, original));
            }

            /* Check that the blobs weren't shallow copied */
            EXPECT_NOT_EQUAL(original->early_data_config.application_protocol.data,
                    clone->early_data_config.application_protocol.data);
            EXPECT_NOT_EQUAL(original->early_data_config.context.data, clone->early_data_config.context.data);

            /* Free the original to ensure they share no memory */
            EXPECT_SUCCESS(s2n_psk_free(&original));

            /* existing alpn is replaced by original's alpn */
            EXPECT_EQUAL(clone->early_data_config.application_protocol.size, sizeof(test_apln));
            EXPECT_BYTEARRAY_EQUAL(clone->early_data_config.application_protocol.data, test_apln, sizeof(test_apln));

            /* new context is allocated for original's context */
            EXPECT_EQUAL(clone->early_data_config.context.size, sizeof(test_context));
            EXPECT_BYTEARRAY_EQUAL(clone->early_data_config.context.data, test_context, sizeof(test_context));

            /* other values are copied */
            EXPECT_EQUAL(clone->early_data_config.max_early_data_size, test_max_early_data);
            EXPECT_EQUAL(clone->early_data_config.cipher_suite, test_cipher_suite);
            EXPECT_EQUAL(clone->early_data_config.protocol_version, test_version);
        }
    };

    /* Test s2n_early_data_is_valid_for_connection */
    {
        /* Safety check */
        EXPECT_FALSE(s2n_early_data_is_valid_for_connection(NULL));

        /* Not valid if the first wire PSK was not chosen
        *
        *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
        *= type=test
        *# In order to accept early data, the server MUST have accepted a PSK
        *# cipher suite and selected the first key offered in the client's
        *# "pre_shared_key" extension.
        **/
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
            conn->actual_protocol_version = S2N_TLS13;
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;

            /* No chosen PSK */
            EXPECT_NULL(conn->psk_params.chosen_psk);
            EXPECT_FALSE(s2n_early_data_is_valid_for_connection(conn));

            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));

            /* PSK chosen, but not first PSK */
            conn->psk_params.chosen_psk_wire_index = 5;
            EXPECT_FALSE(s2n_early_data_is_valid_for_connection(conn));

            /* First PSK chosen */
            conn->psk_params.chosen_psk_wire_index = 0;
            EXPECT_TRUE(s2n_early_data_is_valid_for_connection(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /**
        *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
        *= type=test
        *# In addition, it MUST verify that the
        *# following values are the same as those associated with the
        *# selected PSK:
        **/
        {
            /**
            *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
            *= type=test
            *# -  The TLS version number
            **/
            {
                struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
                EXPECT_NOT_NULL(conn);
                EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
                EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
                conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
                conn->early_data_state = S2N_EARLY_DATA_REQUESTED;

                conn->actual_protocol_version = S2N_TLS12;
                EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS12));
                EXPECT_FALSE(s2n_early_data_is_valid_for_connection(conn));

                /* Reset state machine */
                conn->handshake.state_machine = S2N_STATE_MACHINE_INITIAL;

                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
                EXPECT_TRUE(s2n_early_data_is_valid_for_connection(conn));

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };

            /**
            *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
            *= type=test
            *# -  The selected cipher suite
            **/
            {
                struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
                EXPECT_NOT_NULL(conn);
                EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
                EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
                EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
                conn->actual_protocol_version = S2N_TLS13;
                conn->early_data_state = S2N_EARLY_DATA_REQUESTED;

                conn->secure->cipher_suite = &s2n_tls13_chacha20_poly1305_sha256;
                EXPECT_FALSE(s2n_early_data_is_valid_for_connection(conn));

                conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
                EXPECT_TRUE(s2n_early_data_is_valid_for_connection(conn));

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };

            /**
            *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
            *= type=test
            *# -  The selected ALPN [RFC7301] protocol, if any
            **/
            {
                struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
                EXPECT_NOT_NULL(conn);
                EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
                EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
                conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
                conn->early_data_state = S2N_EARLY_DATA_REQUESTED;

                const uint8_t empty_protocol[] = "";
                const uint8_t required_protocol[] = "required_protocol";
                const uint8_t wrong_protocol[] = "wrong protocol";

                /* No early data alpn set, no alpn negotiated */
                EXPECT_TRUE(s2n_early_data_is_valid_for_connection(conn));

                /* No early data alpn set, but alpn negotiated */
                EXPECT_MEMCPY_SUCCESS(conn->application_protocol, required_protocol, sizeof(required_protocol));
                EXPECT_FALSE(s2n_early_data_is_valid_for_connection(conn));

                EXPECT_SUCCESS(s2n_psk_set_application_protocol(conn->psk_params.chosen_psk,
                        required_protocol, sizeof(required_protocol)));

                /* Early data alpn set, but no alpn negotiated */
                EXPECT_MEMCPY_SUCCESS(conn->application_protocol, empty_protocol, sizeof(empty_protocol));
                EXPECT_FALSE(s2n_early_data_is_valid_for_connection(conn));

                /* Early data alpn does NOT match negotiated alpn */
                EXPECT_MEMCPY_SUCCESS(conn->application_protocol, wrong_protocol, sizeof(wrong_protocol));
                EXPECT_FALSE(s2n_early_data_is_valid_for_connection(conn));

                /* Early data alpn matches negotiated alpn */
                EXPECT_MEMCPY_SUCCESS(conn->application_protocol, required_protocol, sizeof(required_protocol));
                EXPECT_TRUE(s2n_early_data_is_valid_for_connection(conn));

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };
        };
    };

    /* Test s2n_early_data_accept_or_reject */
    {
        /* Safety check */
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_accept_or_reject(NULL), S2N_ERR_NULL);

        /* Server */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

            /* Early data not enabled */
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_early_data_accept_or_reject(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(conn));

            /* Early data not requested */
            conn->early_data_state = S2N_EARLY_DATA_NOT_REQUESTED;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_early_data_accept_or_reject(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_NOT_REQUESTED);

            /* Set wrong protocol version */
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_OK(s2n_early_data_accept_or_reject(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_early_data_accept_or_reject(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Client */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

            /* Early data not enabled */
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_early_data_accept_or_reject(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_REQUESTED);

            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(conn));

            /* Early data not requested */
            conn->early_data_state = S2N_EARLY_DATA_NOT_REQUESTED;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_early_data_accept_or_reject(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_NOT_REQUESTED);

            /* Set wrong protocol version */
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_OK(s2n_early_data_accept_or_reject(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_early_data_accept_or_reject(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_REQUESTED);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Triggers callback to let application reject early data */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);

            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(conn));
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->actual_protocol_version = S2N_TLS13;

            /* Without callback set, accepts early data */
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_OK(s2n_early_data_accept_or_reject(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);

            uint8_t accept_early_data = true;
            EXPECT_SUCCESS(s2n_config_set_early_data_cb(config, s2n_test_early_data_cb));

            /* With callback set, may still accept early data */
            conn->handshake.early_data_async_state = (struct s2n_offered_early_data){ 0 };
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_SUCCESS(s2n_psk_set_early_data_context(conn->psk_params.chosen_psk, &accept_early_data, sizeof(accept_early_data)));
            EXPECT_OK(s2n_early_data_accept_or_reject(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);

            /* With callback set, may reject early data */
            accept_early_data = false;
            conn->handshake.early_data_async_state = (struct s2n_offered_early_data){ 0 };
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_SUCCESS(s2n_psk_set_early_data_context(conn->psk_params.chosen_psk, &accept_early_data, sizeof(accept_early_data)));
            EXPECT_OK(s2n_early_data_accept_or_reject(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* Application rejects early data asynchronously */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_SUCCESS(s2n_config_set_early_data_cb(config, s2n_test_async_early_data_cb));
            EXPECT_NOT_NULL(config);

            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(conn));
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
            conn->actual_protocol_version = S2N_TLS13;
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;

            /* No decision yet: blocked */
            EXPECT_ERROR_WITH_ERRNO(s2n_early_data_accept_or_reject(conn), S2N_ERR_ASYNC_BLOCKED);
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_REQUESTED);

            /* If called again, still blocked */
            EXPECT_ERROR_WITH_ERRNO(s2n_early_data_accept_or_reject(conn), S2N_ERR_ASYNC_BLOCKED);
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_REQUESTED);

            /* Make decision */
            EXPECT_SUCCESS(s2n_offered_early_data_reject(async_early_data));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            /* Complete */
            EXPECT_OK(s2n_early_data_accept_or_reject(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };
    };

    /* Test s2n_connection_get_early_data_status */
    {
        const uint32_t limit = 10;

        /* Safety */
        {
            struct s2n_connection conn = { 0 };
            s2n_early_data_status_t status = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_early_data_status(NULL, &status), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_early_data_status(&conn, NULL), S2N_ERR_NULL);

            conn.early_data_state = S2N_EARLY_DATA_STATES_COUNT;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_early_data_status(&conn, &status), S2N_ERR_INVALID_EARLY_DATA_STATE);
        };

        /* Correct status returned for current early data state */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, limit, &s2n_tls13_aes_256_gcm_sha384));

            s2n_early_data_status_t status = 0;

            EXPECT_SUCCESS(s2n_connection_get_early_data_status(conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_OK);

            conn->early_data_state = S2N_EARLY_DATA_NOT_REQUESTED;
            EXPECT_SUCCESS(s2n_connection_get_early_data_status(conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_NOT_REQUESTED);

            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_SUCCESS(s2n_connection_get_early_data_status(conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_OK);

            conn->early_data_state = S2N_EARLY_DATA_REJECTED;
            EXPECT_SUCCESS(s2n_connection_get_early_data_status(conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_REJECTED);

            conn->early_data_state = S2N_EARLY_DATA_ACCEPTED;
            EXPECT_SUCCESS(s2n_connection_get_early_data_status(conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_OK);

            conn->early_data_state = S2N_END_OF_EARLY_DATA;
            EXPECT_SUCCESS(s2n_connection_get_early_data_status(conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_END);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Sanity check that all valid early data states successfully report a status */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, limit, &s2n_tls13_aes_256_gcm_sha384));

            s2n_early_data_status_t status = 0;
            for (s2n_early_data_state state = 1; state < S2N_EARLY_DATA_STATES_COUNT; state++) {
                conn->early_data_state = state;
                EXPECT_SUCCESS(s2n_connection_get_early_data_status(conn, &status));
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test s2n_connection_get_remaining_early_data_size */
    {
        const uint32_t limit = 10;

        /* Safety */
        {
            struct s2n_connection conn = { 0 };
            uint32_t bytes = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_remaining_early_data_size(NULL, &bytes), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_remaining_early_data_size(&conn, NULL), S2N_ERR_NULL);
        };

        /* If early data allowed, return the remaining bytes allowed */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, limit, &s2n_tls13_aes_256_gcm_sha384));

            uint32_t bytes = 0;

            EXPECT_SUCCESS(s2n_connection_get_remaining_early_data_size(conn, &bytes));
            EXPECT_EQUAL(bytes, limit);

            conn->early_data_state = S2N_EARLY_DATA_NOT_REQUESTED;
            EXPECT_SUCCESS(s2n_connection_get_remaining_early_data_size(conn, &bytes));
            EXPECT_EQUAL(bytes, 0);

            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_SUCCESS(s2n_connection_get_remaining_early_data_size(conn, &bytes));
            EXPECT_EQUAL(bytes, limit);

            conn->early_data_bytes = limit - 1;
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_SUCCESS(s2n_connection_get_remaining_early_data_size(conn, &bytes));
            EXPECT_EQUAL(bytes, 1);

            conn->early_data_bytes = limit;
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_SUCCESS(s2n_connection_get_remaining_early_data_size(conn, &bytes));
            EXPECT_EQUAL(bytes, 0);

            conn->early_data_bytes = limit + 1;
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_remaining_early_data_size(conn, &bytes),
                    S2N_ERR_MAX_EARLY_DATA_SIZE);
            EXPECT_EQUAL(bytes, 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test that all valid early data states successfully report a zero size */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            uint32_t size = 0;
            for (s2n_early_data_state state = 0; state < S2N_EARLY_DATA_STATES_COUNT; state++) {
                conn->early_data_state = state;
                EXPECT_SUCCESS(s2n_connection_get_remaining_early_data_size(conn, &size));
                EXPECT_EQUAL(size, 0);
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test that if S2N_EARLY_DATA_STATUS_OK, then non-zero size reported */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, limit, &s2n_tls13_aes_256_gcm_sha384));

            s2n_early_data_status_t reason = 0;
            uint32_t size = 0;
            for (s2n_early_data_state state = 0; state < S2N_EARLY_DATA_STATES_COUNT; state++) {
                conn->early_data_state = state;

                EXPECT_SUCCESS(s2n_connection_get_early_data_status(conn, &reason));
                EXPECT_SUCCESS(s2n_connection_get_remaining_early_data_size(conn, &size));

                if (reason == S2N_EARLY_DATA_STATUS_OK) {
                    EXPECT_EQUAL(size, limit);
                } else {
                    EXPECT_EQUAL(size, 0);
                }
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test s2n_connection_get_max_early_data_size */
    {
        /* Safety */
        {
            struct s2n_connection conn = { 0 };
            uint32_t bytes = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_max_early_data_size(&conn, NULL), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_max_early_data_size(NULL, &bytes), S2N_ERR_NULL);
            EXPECT_EQUAL(bytes, 0);
        };

        /* Retrieve the limit from the first PSK, or return 0 */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            const uint32_t limit = 10;
            uint32_t actual_bytes = limit;

            /* No PSKs: limit is zero */
            EXPECT_SUCCESS(s2n_connection_get_max_early_data_size(conn, &actual_bytes));
            EXPECT_EQUAL(actual_bytes, 0);

            /* PSK with zero limit: limit is zero */
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, 0, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_SUCCESS(s2n_connection_get_max_early_data_size(conn, &actual_bytes));
            EXPECT_EQUAL(actual_bytes, 0);

            /* Second PSK with non-zero limit: limit is still zero */
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, limit, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_SUCCESS(s2n_connection_get_max_early_data_size(conn, &actual_bytes));
            EXPECT_EQUAL(actual_bytes, 0);

            /* First PSK with non-zero limit: limit is non-zero */
            EXPECT_OK(s2n_psk_parameters_wipe(&conn->psk_params));
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, limit, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_SUCCESS(s2n_connection_get_max_early_data_size(conn, &actual_bytes));
            EXPECT_EQUAL(actual_bytes, limit);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* If in server mode, apply the server limit */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);

            const uint32_t psk_limit = 10;
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(conn, psk_limit, &s2n_tls13_aes_256_gcm_sha384));

            uint32_t actual_bytes = 0;

            /* server limit is lower, but PSK is external: use PSK limit */
            EXPECT_EQUAL(conn->psk_params.chosen_psk->type, S2N_PSK_TYPE_EXTERNAL);
            uint32_t server_limit = psk_limit - 1;
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, server_limit));
            EXPECT_SUCCESS(s2n_connection_get_max_early_data_size(conn, &actual_bytes));
            EXPECT_EQUAL(actual_bytes, psk_limit);

            conn->psk_params.chosen_psk->type = S2N_PSK_TYPE_RESUMPTION;

            /* server limit is higher: use PSK limit */
            server_limit = psk_limit + 1;
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, server_limit));
            EXPECT_SUCCESS(s2n_connection_get_max_early_data_size(conn, &actual_bytes));
            EXPECT_EQUAL(actual_bytes, psk_limit);

            /* server limit is lower and PSK is resumption: use server limit */
            server_limit = psk_limit - 1;
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, server_limit));
            EXPECT_SUCCESS(s2n_connection_get_max_early_data_size(conn, &actual_bytes));
            EXPECT_EQUAL(actual_bytes, server_limit);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* If in server mode, fall back to the server limit */
        {
            const uint32_t server_limit = 15;
            uint32_t actual_bytes = 0;

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);

            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);

            /* No PSKs: use server limit for initial connection */
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(server_conn, server_limit));
            EXPECT_SUCCESS(s2n_connection_get_max_early_data_size(server_conn, &actual_bytes));
            EXPECT_EQUAL(actual_bytes, server_limit);

            /* Client mode: don't use server limit for initial connection */
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(client_conn, server_limit));
            EXPECT_SUCCESS(s2n_connection_get_max_early_data_size(client_conn, &actual_bytes));
            EXPECT_EQUAL(actual_bytes, 0);

            /* Negotiated connection: once a connection is negotiated, no PSKs means no early data */
            server_conn->handshake.handshake_type = NEGOTIATED;
            EXPECT_SUCCESS(s2n_connection_get_max_early_data_size(server_conn, &actual_bytes));
            EXPECT_EQUAL(actual_bytes, 0);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };
    };

    /* Test s2n_config_set_server_max_early_data_size */
    {
        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_server_max_early_data_size(NULL, 1), S2N_ERR_NULL);

        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);

        EXPECT_EQUAL(config->server_max_early_data_size, 0);

        EXPECT_SUCCESS(s2n_config_set_server_max_early_data_size(config, 1));
        EXPECT_EQUAL(config->server_max_early_data_size, 1);

        EXPECT_SUCCESS(s2n_config_set_server_max_early_data_size(config, UINT32_MAX));
        EXPECT_EQUAL(config->server_max_early_data_size, UINT32_MAX);

        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test s2n_connection_set_server_max_early_data_size */
    {
        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_server_max_early_data_size(NULL, 1), S2N_ERR_NULL);

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        EXPECT_EQUAL(conn->server_max_early_data_size, 0);
        EXPECT_FALSE(conn->server_max_early_data_size_overridden);

        EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, 1));
        EXPECT_EQUAL(conn->server_max_early_data_size, 1);
        EXPECT_TRUE(conn->server_max_early_data_size_overridden);

        conn->server_max_early_data_size_overridden = false;

        EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, UINT32_MAX));
        EXPECT_EQUAL(conn->server_max_early_data_size, UINT32_MAX);
        EXPECT_TRUE(conn->server_max_early_data_size_overridden);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_early_data_get_server_max_size */
    {
        uint32_t result_size = 0;
        const uint32_t connection_value = 10;
        const uint32_t config_value = 5;

        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_server_max_early_data_size(config, config_value));

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, connection_value));

        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_get_server_max_size(NULL, &result_size), S2N_ERR_NULL);
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_get_server_max_size(conn, NULL), S2N_ERR_NULL);

        /* No config */
        conn->config = NULL;
        conn->server_max_early_data_size_overridden = false;
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_get_server_max_size(conn, &result_size), S2N_ERR_NULL);

        /* No config, but connection override set */
        EXPECT_NULL(conn->config);
        conn->server_max_early_data_size_overridden = true;
        EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, connection_value));
        EXPECT_OK(s2n_early_data_get_server_max_size(conn, &result_size));
        EXPECT_EQUAL(result_size, connection_value);

        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Return config version if override not set */
        conn->server_max_early_data_size_overridden = false;
        EXPECT_OK(s2n_early_data_get_server_max_size(conn, &result_size));
        EXPECT_EQUAL(result_size, config_value);

        /* Return connection version if set */
        conn->server_max_early_data_size_overridden = true;
        EXPECT_OK(s2n_early_data_get_server_max_size(conn, &result_size));
        EXPECT_EQUAL(result_size, connection_value);

        /* Connection can override with a zero value */
        EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(conn, 0));
        EXPECT_OK(s2n_early_data_get_server_max_size(conn, &result_size));
        EXPECT_EQUAL(result_size, 0);

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_connection_set_server_early_data_context */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        const uint8_t data[] = "hello world";

        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_server_early_data_context(NULL, data, 1), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_server_early_data_context(conn, NULL, 1), S2N_ERR_NULL);
        EXPECT_EQUAL(conn->server_early_data_context.size, 0);
        EXPECT_EQUAL(conn->server_early_data_context.allocated, 0);

        /* Set context */
        EXPECT_SUCCESS(s2n_connection_set_server_early_data_context(conn, data, sizeof(data)));
        EXPECT_EQUAL(conn->server_early_data_context.size, sizeof(data));
        EXPECT_BYTEARRAY_EQUAL(conn->server_early_data_context.data, data, sizeof(data));

        /* Clear context */
        EXPECT_SUCCESS(s2n_connection_set_server_early_data_context(conn, NULL, 0));
        EXPECT_EQUAL(conn->server_early_data_context.size, 0);

        /* Set context again */
        EXPECT_SUCCESS(s2n_connection_set_server_early_data_context(conn, data, 1));
        EXPECT_EQUAL(conn->server_early_data_context.size, 1);
        EXPECT_BYTEARRAY_EQUAL(conn->server_early_data_context.data, data, 1);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_early_data_record_bytes */
    {
        /* Safety check */
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_record_bytes(NULL, 1), S2N_ERR_NULL);

        const uint32_t limit = 10;

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_append_test_psk_with_early_data(conn, limit, &s2n_tls13_aes_256_gcm_sha384));

        /* If early data not expected, bytes are not recorded */
        conn->early_data_bytes = 0;
        EXPECT_OK(s2n_early_data_record_bytes(conn, limit + 1));
        EXPECT_EQUAL(conn->early_data_bytes, 0);

        EXPECT_SUCCESS(s2n_connection_set_early_data_expected(conn));

        /* Bytes are recorded */
        {
            conn->early_data_bytes = 0;
            EXPECT_OK(s2n_early_data_record_bytes(conn, 1));
            EXPECT_EQUAL(conn->early_data_bytes, 1);

            conn->early_data_bytes = 1;
            EXPECT_OK(s2n_early_data_record_bytes(conn, 1));
            EXPECT_EQUAL(conn->early_data_bytes, 2);
        };

        /* Error if exceeds max_early_data_size */
        {
            conn->early_data_bytes = 0;
            EXPECT_OK(s2n_early_data_record_bytes(conn, limit));
            EXPECT_EQUAL(conn->early_data_bytes, limit);

            conn->early_data_bytes = 1;
            EXPECT_ERROR_WITH_ERRNO(s2n_early_data_record_bytes(conn, limit), S2N_ERR_MAX_EARLY_DATA_SIZE);
            EXPECT_EQUAL(conn->early_data_bytes, limit + 1);
        };

        /* Prevents early_data_bytes from overflowing */
        {
            conn->early_data_bytes = UINT64_MAX - 2;
            EXPECT_ERROR_WITH_ERRNO(s2n_early_data_record_bytes(conn, 1), S2N_ERR_MAX_EARLY_DATA_SIZE);
            EXPECT_EQUAL(conn->early_data_bytes, UINT64_MAX - 1);

            conn->early_data_bytes = UINT64_MAX - 1;
            EXPECT_ERROR_WITH_ERRNO(s2n_early_data_record_bytes(conn, 1), S2N_ERR_MAX_EARLY_DATA_SIZE);
            EXPECT_EQUAL(conn->early_data_bytes, UINT64_MAX);

            conn->early_data_bytes = UINT64_MAX;
            EXPECT_ERROR_WITH_ERRNO(s2n_early_data_record_bytes(conn, 1), S2N_ERR_INTEGER_OVERFLOW);
            EXPECT_EQUAL(conn->early_data_bytes, UINT64_MAX);
        };

        /* Zero bytes are "recorded" */
        {
            conn->early_data_bytes = 0;
            EXPECT_OK(s2n_early_data_record_bytes(conn, 0));
            EXPECT_EQUAL(conn->early_data_bytes, 0);

            conn->early_data_bytes = limit;
            EXPECT_OK(s2n_early_data_record_bytes(conn, 0));
            EXPECT_EQUAL(conn->early_data_bytes, limit);

            conn->early_data_bytes = limit + 1;
            EXPECT_ERROR_WITH_ERRNO(s2n_early_data_record_bytes(conn, 0), S2N_ERR_MAX_EARLY_DATA_SIZE);
            EXPECT_EQUAL(conn->early_data_bytes, limit + 1);
        };

        /* Negative bytes are "recorded" */
        {
            conn->early_data_bytes = 0;
            EXPECT_OK(s2n_early_data_record_bytes(conn, -1));
            EXPECT_EQUAL(conn->early_data_bytes, 0);

            conn->early_data_bytes = limit / 2;
            EXPECT_OK(s2n_early_data_record_bytes(conn, -1));
            EXPECT_EQUAL(conn->early_data_bytes, limit / 2);

            conn->early_data_bytes = limit;
            EXPECT_OK(s2n_early_data_record_bytes(conn, -1));
            EXPECT_EQUAL(conn->early_data_bytes, limit);

            /* Unlike with other inputs, does not return an error and set S2N_ERR_MAX_EARLY_DATA_SIZE.
             * That would overwrite whatever send error caused the -1 result.
             */
            conn->early_data_bytes = limit + 1;
            EXPECT_OK(s2n_early_data_record_bytes(conn, -1));
            EXPECT_EQUAL(conn->early_data_bytes, limit + 1);
        };

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_early_data_validate_send */
    {
        /* Safety check */
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_validate_send(NULL, 1), S2N_ERR_NULL);

        const uint32_t limit = 10;
        struct s2n_connection *valid_connection = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(valid_connection);
        EXPECT_OK(s2n_append_test_psk_with_early_data(valid_connection, limit, &s2n_tls13_aes_256_gcm_sha384));
        EXPECT_SUCCESS(s2n_connection_set_early_data_expected(valid_connection));
        valid_connection->mode = S2N_CLIENT;
        valid_connection->early_data_state = S2N_EARLY_DATA_REQUESTED;
        valid_connection->early_data_bytes = 0;

        /* Fails if server */
        struct s2n_connection conn = *valid_connection;
        conn.mode = S2N_SERVER;
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_validate_send(&conn, 1), S2N_ERR_EARLY_DATA_NOT_ALLOWED);

        /* Fails if wrong state */
        conn = *valid_connection;
        conn.early_data_state = S2N_END_OF_EARLY_DATA;
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_validate_send(&conn, 1), S2N_ERR_EARLY_DATA_NOT_ALLOWED);

        /* Passes for S2N_EARLY_DATA_REQUESTED */
        conn = *valid_connection;
        conn.early_data_state = S2N_EARLY_DATA_REQUESTED;
        EXPECT_OK(s2n_early_data_validate_send(&conn, 1));

        /* Passes for S2N_EARLY_DATA_ACCEPTED */
        conn = *valid_connection;
        conn.early_data_state = S2N_EARLY_DATA_ACCEPTED;
        EXPECT_OK(s2n_early_data_validate_send(&conn, 1));

        /* Fails if too much data */
        conn = *valid_connection;
        conn.early_data_bytes = limit;
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_validate_send(&conn, 1), S2N_ERR_MAX_EARLY_DATA_SIZE);

        /* No-op if actually Application Data */
        conn = *valid_connection;
        conn.early_data_bytes = limit;
        conn.handshake.handshake_type = NEGOTIATED;
        while (s2n_conn_get_current_message_type(&conn) != APPLICATION_DATA) {
            conn.handshake.message_number++;
        }
        EXPECT_OK(s2n_early_data_validate_send(&conn, 1));

        EXPECT_SUCCESS(s2n_connection_free(valid_connection));
    };

    /* Test s2n_early_data_validate_recv */
    {
        /* Safety check */
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_validate_recv(NULL), S2N_ERR_NULL);

        const uint32_t limit = 10;
        struct s2n_connection *valid_connection = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(valid_connection);
        EXPECT_OK(s2n_append_test_psk_with_early_data(valid_connection, limit, &s2n_tls13_aes_256_gcm_sha384));
        EXPECT_SUCCESS(s2n_connection_set_early_data_expected(valid_connection));
        valid_connection->early_data_state = S2N_EARLY_DATA_ACCEPTED;
        valid_connection->early_data_bytes = 0;
        valid_connection->actual_protocol_version = S2N_TLS13;
        EXPECT_OK(s2n_conn_choose_state_machine(valid_connection, S2N_TLS13));
        valid_connection->handshake.handshake_type = NEGOTIATED | WITH_EARLY_DATA;
        while (s2n_conn_get_current_message_type(valid_connection) != END_OF_EARLY_DATA) {
            valid_connection->handshake.message_number++;
        }

        /* Passes if everything valid */
        struct s2n_connection conn = *valid_connection;
        EXPECT_OK(s2n_early_data_validate_recv(&conn));

        /* Fails if client */
        conn = *valid_connection;
        conn.mode = S2N_CLIENT;
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_validate_recv(&conn), S2N_ERR_EARLY_DATA_NOT_ALLOWED);

        /* Fails if wrong state */
        conn = *valid_connection;
        conn.early_data_state = S2N_END_OF_EARLY_DATA;
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_validate_recv(&conn), S2N_ERR_EARLY_DATA_NOT_ALLOWED);

        /* Fails if wrong handshake message */
        conn = *valid_connection;
        conn.handshake.message_number--;
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_validate_recv(&conn), S2N_ERR_EARLY_DATA_NOT_ALLOWED);

        /* Fails for S2N_EARLY_DATA_REQUESTED */
        conn = *valid_connection;
        conn.early_data_state = S2N_EARLY_DATA_REQUESTED;
        EXPECT_ERROR_WITH_ERRNO(s2n_early_data_validate_recv(&conn), S2N_ERR_EARLY_DATA_NOT_ALLOWED);

        /* Passes for S2N_EARLY_DATA_ACCEPTED */
        conn = *valid_connection;
        conn.early_data_state = S2N_EARLY_DATA_ACCEPTED;
        EXPECT_OK(s2n_early_data_validate_recv(&conn));

        /* No-op if actually Application Data */
        conn = *valid_connection;
        conn.early_data_bytes = limit;
        conn.handshake.handshake_type = NEGOTIATED;
        while (s2n_conn_get_current_message_type(&conn) != APPLICATION_DATA) {
            conn.handshake.message_number++;
        }
        EXPECT_OK(s2n_early_data_validate_recv(&conn));

        EXPECT_SUCCESS(s2n_connection_free(valid_connection));
    };

    /* Test s2n_config_set_early_data_cb */
    {
        struct s2n_config *config = s2n_config_new();

        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_early_data_cb(NULL, s2n_test_early_data_cb), S2N_ERR_NULL);
        EXPECT_EQUAL(config->early_data_cb, 0);

        /* Set callback */
        EXPECT_SUCCESS(s2n_config_set_early_data_cb(config, s2n_test_early_data_cb));
        EXPECT_EQUAL(config->early_data_cb, s2n_test_early_data_cb);

        /* Clear callback */
        EXPECT_SUCCESS(s2n_config_set_early_data_cb(config, NULL));
        EXPECT_EQUAL(config->early_data_cb, NULL);

        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test s2n_offered_early_data_get_context and s2n_offered_early_data_get_context_length */
    {
        struct s2n_offered_early_data early_data = { 0 };
        const uint8_t context[] = "psk context";
        const uint8_t empty_context[sizeof(context)] = { 0 };
        uint8_t actual_context[sizeof(context)] = { 0 };
        uint16_t length = 1;

        /* Safety */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_early_data_get_context_length(NULL, &length), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_early_data_get_context(NULL, actual_context, 1), S2N_ERR_NULL);

            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_early_data_get_context_length(&early_data, NULL), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_early_data_get_context(&early_data, NULL, 1), S2N_ERR_NULL);

            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_early_data_get_context_length(&early_data, &length), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_early_data_get_context(&early_data, actual_context, 1), S2N_ERR_NULL);

            early_data.conn = s2n_connection_new(S2N_SERVER);
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_early_data_get_context_length(&early_data, &length), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_early_data_get_context(&early_data, actual_context, 1), S2N_ERR_NULL);
            EXPECT_SUCCESS(s2n_connection_free(early_data.conn));
        };

        /* No context */
        {
            early_data.conn = s2n_connection_new(S2N_SERVER);
            DEFER_CLEANUP(struct s2n_psk *test_psk = s2n_test_psk_new(early_data.conn), s2n_psk_free);
            early_data.conn->psk_params.chosen_psk = test_psk;

            EXPECT_SUCCESS(s2n_offered_early_data_get_context_length(&early_data, &length));
            EXPECT_EQUAL(length, 0);

            EXPECT_SUCCESS(s2n_offered_early_data_get_context(&early_data, actual_context, 0));
            EXPECT_BYTEARRAY_EQUAL(actual_context, empty_context, sizeof(empty_context));

            EXPECT_SUCCESS(s2n_offered_early_data_get_context(&early_data, actual_context, sizeof(actual_context)));
            EXPECT_BYTEARRAY_EQUAL(actual_context, empty_context, sizeof(empty_context));

            EXPECT_SUCCESS(s2n_connection_free(early_data.conn));
        };

        /* Context */
        {
            early_data.conn = s2n_connection_new(S2N_SERVER);
            DEFER_CLEANUP(struct s2n_psk *test_psk = s2n_test_psk_new(early_data.conn), s2n_psk_free);
            EXPECT_SUCCESS(s2n_psk_set_early_data_context(test_psk, context, sizeof(context)));
            early_data.conn->psk_params.chosen_psk = test_psk;

            EXPECT_SUCCESS(s2n_offered_early_data_get_context_length(&early_data, &length));
            EXPECT_EQUAL(length, sizeof(context));

            EXPECT_SUCCESS(s2n_offered_early_data_get_context(&early_data, actual_context, sizeof(actual_context)));
            EXPECT_BYTEARRAY_EQUAL(actual_context, context, sizeof(context));

            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_early_data_get_context(&early_data, actual_context, 1),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);

            EXPECT_SUCCESS(s2n_connection_free(early_data.conn));
        };
    };

    /* Test s2n_offered_early_data_reject */
    {
        struct s2n_offered_early_data early_data = { .conn = NULL };

        /* Safety */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_early_data_reject(NULL), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_early_data_reject(&early_data), S2N_ERR_NULL);
        };

        /* Reject early data */
        {
            early_data.conn = s2n_connection_new(S2N_SERVER);
            early_data.conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_SUCCESS(s2n_offered_early_data_reject(&early_data));
            EXPECT_EQUAL(early_data.conn->early_data_state, S2N_EARLY_DATA_REJECTED);
            EXPECT_SUCCESS(s2n_connection_free(early_data.conn));
        };
    };

    /* Test s2n_offered_early_data_accept */
    {
        struct s2n_offered_early_data early_data = { .conn = NULL };

        /* Safety */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_early_data_accept(NULL), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_early_data_accept(&early_data), S2N_ERR_NULL);
        };

        /* Accept early data */
        {
            early_data.conn = s2n_connection_new(S2N_SERVER);
            early_data.conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_SUCCESS(s2n_offered_early_data_accept(&early_data));
            EXPECT_EQUAL(early_data.conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);
            EXPECT_SUCCESS(s2n_connection_free(early_data.conn));
        };
    };

    END_TEST();
}
