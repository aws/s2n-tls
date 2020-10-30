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

#include "tls/extensions/s2n_client_pq_kem.h"
#include "tls/s2n_security_policies.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13());

#if !defined(S2N_NO_PQ)

    const char* pq_security_policies[] = {
            "KMS-PQ-TLS-1-0-2020-02",
            "KMS-PQ-TLS-1-0-2020-07"
    };

    for (size_t policy_index = 0; policy_index < s2n_array_len(pq_security_policies); policy_index++) {
        const char *pq_security_policy = pq_security_policies[policy_index];
        const struct s2n_security_policy *security_policy;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version(pq_security_policy, &security_policy));
        const struct s2n_kem_preferences *kem_preferences = security_policy->kem_preferences;

        /* Test should_send */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            /* Default cipher preferences do not include PQ, so extension not sent */
            EXPECT_FALSE(s2n_client_pq_kem_extension.should_send(conn));

            /* Use cipher preferences that do include PQ */
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, pq_security_policy));
            EXPECT_TRUE(s2n_client_pq_kem_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test send */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, pq_security_policy));

            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_SUCCESS(s2n_client_pq_kem_extension.send(conn, &stuffer));

            /* Should write correct size */
            uint16_t size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &size));
            EXPECT_EQUAL(size, s2n_stuffer_data_available(&stuffer));
            EXPECT_EQUAL(size, kem_preferences->kem_count * sizeof(kem_extension_size));

            /* Should write ids */
            uint16_t actual_id;
            for (size_t i = 0; i < kem_preferences->kem_count; i++) {
                GUARD(s2n_stuffer_read_uint16(&stuffer, &actual_id));
                EXPECT_EQUAL(actual_id, kem_preferences->kems[i]->kem_extension_id);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test receive - malformed length */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, pq_security_policy));

            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_SUCCESS(s2n_client_pq_kem_extension.send(conn, &stuffer));
            EXPECT_SUCCESS(s2n_stuffer_wipe_n(&stuffer, 1));

            EXPECT_SUCCESS(s2n_client_pq_kem_extension.recv(conn, &stuffer));
            EXPECT_EQUAL(conn->secure.client_pq_kem_extension.size, 0);
            EXPECT_NULL(conn->secure.client_pq_kem_extension.data);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test receive */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, pq_security_policy));

            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_SUCCESS(s2n_client_pq_kem_extension.send(conn, &stuffer));

            EXPECT_SUCCESS(s2n_client_pq_kem_extension.recv(conn, &stuffer));
            EXPECT_EQUAL(conn->secure.client_pq_kem_extension.size, kem_preferences->kem_count * sizeof(kem_extension_size));
            EXPECT_NOT_NULL(conn->secure.client_pq_kem_extension.data);
            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }
#endif

    END_TEST();
}
