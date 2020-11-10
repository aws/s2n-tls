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
#include "tls/s2n_connection.h"
#include "tls/s2n_crypto.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13());
    struct s2n_connection *conn;

    /* Test valid psk identities */
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_psk_identity psk_identity_vec[] = {
            { .identity = "test_psk_1", .obfuscated_ticket_age = 0, .hash_algorithm = S2N_HASH_SHA256 },
            { .identity = "test_psk_2", .obfuscated_ticket_age = 0, .hash_algorithm = S2N_HASH_SHA384 },
        };

        size_t psk_identity_vlen = sizeof(psk_identity_vec) / sizeof(psk_identity_vec[0]);

        EXPECT_SUCCESS(s2n_connection_set_client_psk_identities(conn, psk_identity_vec, psk_identity_vlen));

        for (size_t i = 0; i < psk_identity_vlen; i++) {
            EXPECT_TRUE(strcmp(conn->initial.client_psk_config.psk_vec[i].identity, psk_identity_vec[i].identity) == 0);
            EXPECT_TRUE(conn->initial.client_psk_config.psk_vec[i].obfuscated_ticket_age == 0);
            EXPECT_TRUE(conn->initial.client_psk_config.psk_vec[i].hash_algorithm
                        == psk_identity_vec[i].hash_algorithm);
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test failure when PSK Identity is a NULL value */
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        struct s2n_psk_identity psk_identity_vec[] = { 0 };
        size_t psk_identity_vlen = sizeof(psk_identity_vec) / sizeof(psk_identity_vec[0]);
        EXPECT_FAILURE(s2n_connection_set_client_psk_identities(conn, psk_identity_vec, psk_identity_vlen));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test failure for invalid psk identity vector size */
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        size_t invalid_psk_id_vec_len = 100;
        struct s2n_psk_identity psk_identity_vec[] = { 0 };

        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_client_psk_identities(conn, psk_identity_vec, invalid_psk_id_vec_len),
                                  S2N_ERR_INVALID_PSK_VECTOR_LEN);
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test failure when PSK Identity is not a unique value */
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        struct s2n_psk_identity psk_identity_vec[] = {
            { .identity = "test_psk_1", .obfuscated_ticket_age = 0, .hash_algorithm = S2N_HASH_SHA256 },
            { .identity = "test_psk_2", .obfuscated_ticket_age = 0, .hash_algorithm = S2N_HASH_SHA384 },
            { .identity = "test_psk_1", .obfuscated_ticket_age = 0, .hash_algorithm = S2N_HASH_SHA256 },
        };

        size_t psk_identity_vlen = sizeof(psk_identity_vec) / sizeof(psk_identity_vec[0]);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_client_psk_identities(conn, psk_identity_vec, psk_identity_vlen), S2N_ERR_INVALID_PSK_IDENTITY);
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test that obfuscated_ticket_age is always set to 0 for identities set externally */ 
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        struct s2n_psk_identity psk_identity_vec[] = {
            { .identity = "test_psk_1", .obfuscated_ticket_age = 1234523, .hash_algorithm = S2N_HASH_SHA256 },
            { .identity = "test_psk_2", .obfuscated_ticket_age = 6543111, .hash_algorithm = S2N_HASH_SHA256 },
        };

        size_t psk_identity_vlen = sizeof(psk_identity_vec) / sizeof(psk_identity_vec[0]);
        EXPECT_SUCCESS(s2n_connection_set_client_psk_identities(conn, psk_identity_vec, psk_identity_vlen));

        for (size_t i = 0; i < psk_identity_vlen; i++) {
            EXPECT_TRUE(conn->initial.client_psk_config.psk_vec[i].obfuscated_ticket_age == 0);
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test that Hash Algorithm defaults to SHA-256 if not set */  
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        struct s2n_psk_identity psk_identity_vec[] = {
            { .identity = "test_psk_1", .obfuscated_ticket_age = 0, .hash_algorithm = S2N_HASH_NONE },
        };

        size_t psk_identity_vlen = sizeof(psk_identity_vec) / sizeof(psk_identity_vec[0]);
        EXPECT_SUCCESS(s2n_connection_set_client_psk_identities(conn, psk_identity_vec, psk_identity_vlen));

        for (size_t i = 0; i < psk_identity_vlen; i++) {
            EXPECT_TRUE(conn->initial.client_psk_config.psk_vec[i].hash_algorithm == S2N_HASH_SHA256);
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
}
