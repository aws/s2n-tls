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
        EXPECT_FAILURE_WITH_ERRNO(s2n_psk_configure_early_data(NULL, 1, 1, 1, 1), S2N_ERR_NULL);

        /* Set invalid protocol version */
        {
            struct s2n_psk psk = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_psk_configure_early_data(&psk, 1000, S2N_TLS12, 1, 1),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_EQUAL(psk.early_data_config.max_early_data, 0);
        }

        /* Set valid configuration */
        {
            uint32_t expected_max_early_data = 1000;
            uint8_t expected_protocol_version = S2N_TLS13;
            uint8_t expected_cipher_suite[] = { 0x01, 0xAB };

            struct s2n_psk psk = { 0 };
            EXPECT_SUCCESS(s2n_psk_configure_early_data(&psk, expected_max_early_data, expected_protocol_version,
                    expected_cipher_suite[0], expected_cipher_suite[1]));

            EXPECT_EQUAL(psk.early_data_config.max_early_data, expected_max_early_data);
            EXPECT_EQUAL(psk.early_data_config.protocol_version, expected_protocol_version);
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
