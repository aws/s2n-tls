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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#include "tls/s2n_early_data.h"

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

        ENSURE_EQ(actual_valid, expected_valid);

        if (expected_valid) {
            GUARD_RESULT(s2n_test_all_early_data_sequences(conn, i + 1,
                    valid_early_state_sequences, valid_early_state_sequences_len));
        }
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_alloc_test_config_buffers(struct s2n_early_data_config *config)
{
    GUARD_AS_RESULT(s2n_alloc(&config->application_protocol, TEST_SIZE));
    ENSURE_NE(config->application_protocol.size, 0);
    GUARD_AS_RESULT(s2n_alloc(&config->context, TEST_SIZE));
    ENSURE_NE(config->context.size, 0);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_config_buffers_freed(struct s2n_early_data_config *config)
{
    ENSURE_EQ(config->application_protocol.data, NULL);
    ENSURE_EQ(config->application_protocol.size, 0);
    ENSURE_EQ(config->context.data, NULL);
    ENSURE_EQ(config->context.size, 0);
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    const uint8_t test_value[] = "test value";
    const uint8_t test_value_2[] = "more test data";

    /* Test s2n_connection_set_early_data_state */
    {
        /* Safety check */
        EXPECT_ERROR_WITH_ERRNO(s2n_connection_set_early_data_state(NULL, 0), S2N_ERR_NULL);

        const s2n_early_data_state early_data_not_requested_seq[] = {
                S2N_UNKNOWN_EARLY_DATA_STATE, S2N_EARLY_DATA_NOT_REQUESTED };
        const s2n_early_data_state early_data_rejected_seq[] = {
                S2N_UNKNOWN_EARLY_DATA_STATE, S2N_EARLY_DATA_REQUESTED, S2N_EARLY_DATA_REJECTED };
        const s2n_early_data_state early_data_success_seq[] = {
                S2N_UNKNOWN_EARLY_DATA_STATE, S2N_EARLY_DATA_REQUESTED, S2N_EARLY_DATA_ACCEPTED, S2N_END_OF_EARLY_DATA };

        /* Test known valid / invalid transitions */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);

            conn->early_data_state = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_connection_set_early_data_state(conn, S2N_UNKNOWN_EARLY_DATA_STATE),
                    S2N_ERR_INVALID_EARLY_DATA_STATE);

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
        }

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
            }

            /* Sanity check: adding an invalid expected sequence causes test to fail */
            {
                const s2n_early_data_state invalid_seq[] = {
                        S2N_UNKNOWN_EARLY_DATA_STATE, S2N_EARLY_DATA_ACCEPTED, S2N_END_OF_EARLY_DATA };
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
            }

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
            }
        }
    }

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
        }

        /* Called by s2n_psk_wipe */
        {
            struct s2n_psk psk = { 0 };
            EXPECT_OK(s2n_alloc_test_config_buffers(&psk.early_data_config));

            EXPECT_OK(s2n_psk_wipe(&psk));
            EXPECT_OK(s2n_test_config_buffers_freed(&psk.early_data_config));
        }

        /* Called by s2n_psk_free */
        {
            struct s2n_psk *psk = s2n_external_psk_new();
            EXPECT_OK(s2n_alloc_test_config_buffers(&psk->early_data_config));

            EXPECT_SUCCESS(s2n_psk_free(&psk));
            /* A memory leak in this test would indicate that s2n_psk_free isn't freeing the buffers. */
        }
    }

    /* Test s2n_psk_configure_early_data */
    {
        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_psk_configure_early_data(NULL, 1, 1, 1), S2N_ERR_NULL);

        /* Set valid configuration */
        {
            uint32_t expected_max_early_data_size = 1000;
            uint8_t expected_cipher_suite[] = { 0x01, 0xAB };

            struct s2n_psk psk = { 0 };
            EXPECT_SUCCESS(s2n_psk_configure_early_data(&psk, expected_max_early_data_size,
                    expected_cipher_suite[0], expected_cipher_suite[1]));

            EXPECT_EQUAL(psk.early_data_config.max_early_data_size, expected_max_early_data_size);
            EXPECT_EQUAL(psk.early_data_config.protocol_version, S2N_TLS13);
            EXPECT_BYTEARRAY_EQUAL(psk.early_data_config.cipher_suite_iana, expected_cipher_suite,
                    sizeof(expected_cipher_suite));
        }
    }

    /* Test s2n_psk_set_application_protocol */
    {
        /* Safety checks */
        {
            struct s2n_psk psk = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_application_protocol(&psk, NULL, 1), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_application_protocol(NULL, test_value, 1), S2N_ERR_NULL);
        }

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
    }

    /* Test s2n_psk_set_context */
    {
        /* Safety checks */
        {
            struct s2n_psk psk = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_context(&psk, NULL, 1), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_context(NULL, test_value, 1), S2N_ERR_NULL);
        }

        DEFER_CLEANUP(struct s2n_psk *psk = s2n_external_psk_new(), s2n_psk_free);
        EXPECT_EQUAL(psk->early_data_config.context.size, 0);
        EXPECT_EQUAL(psk->early_data_config.context.allocated, 0);

        /* Set empty value as no-op */
        EXPECT_SUCCESS(s2n_psk_set_context(psk, test_value, 0));
        EXPECT_EQUAL(psk->early_data_config.context.size, 0);
        EXPECT_EQUAL(psk->early_data_config.context.allocated, 0);

        /* Set valid value */
        EXPECT_SUCCESS(s2n_psk_set_context(psk, test_value, sizeof(test_value)));
        EXPECT_EQUAL(psk->early_data_config.context.size, sizeof(test_value));
        EXPECT_BYTEARRAY_EQUAL(psk->early_data_config.context.data, test_value, sizeof(test_value));

        /* Replace previous value */
        EXPECT_SUCCESS(s2n_psk_set_context(psk, test_value_2, sizeof(test_value_2)));
        EXPECT_EQUAL(psk->early_data_config.context.size, sizeof(test_value_2));
        EXPECT_BYTEARRAY_EQUAL(psk->early_data_config.context.data, test_value_2, sizeof(test_value_2));

        /* Clear with empty value */
        EXPECT_SUCCESS(s2n_psk_set_context(psk, test_value, 0));
        EXPECT_EQUAL(psk->early_data_config.context.size, 0);
        EXPECT_EQUAL(psk->early_data_config.context.allocated, 0);

        /* Repeat clear */
        EXPECT_SUCCESS(s2n_psk_set_context(psk, test_value, 0));
        EXPECT_EQUAL(psk->early_data_config.context.size, 0);
        EXPECT_EQUAL(psk->early_data_config.context.allocated, 0);
    }

    END_TEST();
}
