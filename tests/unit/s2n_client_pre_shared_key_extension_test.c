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

#include <stdint.h>

#include "tls/s2n_alerts.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/extensions/s2n_key_share.h"
#include "tls/extensions/s2n_client_pre_shared_key.h"

#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"


int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13());

    struct s2n_psk_identity psk_identity_vec[] = {
        { .identity = "test_psk_1", .obfuscated_ticket_age = 0, .hash_algorithm = S2N_HASH_SHA256 },
        { .identity = "test_psk_2", .obfuscated_ticket_age = 0, .hash_algorithm = S2N_HASH_SHA384 },
    };

    uint16_t psk_identity_vlen = sizeof(psk_identity_vec) / sizeof(psk_identity_vec[0]);

    /* Test s2n_client_pre_shared_key_extension.send */
    {
        /* Test that s2n_client_pre_shared_key_extension sends the PSK Identities and obfuscated_ticket_age succesfully */
        {
            struct s2n_stuffer psk_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_extension, 0));

            EXPECT_SUCCESS(s2n_connection_set_client_psk_identities(conn, psk_identity_vec, psk_identity_vlen));
            EXPECT_SUCCESS(s2n_client_pre_shared_key_extension.send(conn, &psk_extension));

            uint16_t psk_vec_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&psk_extension, &psk_vec_len));
            EXPECT_EQUAL(psk_vec_len, psk_identity_vlen);

            for (size_t i = 0; i < psk_vec_len; i++) {
                uint32_t expected_obf_age;
                EXPECT_SUCCESS(s2n_stuffer_read_expected_str(&psk_extension, psk_identity_vec[i].identity));
                EXPECT_SUCCESS(s2n_stuffer_read_uint32(&psk_extension, &expected_obf_age));
                EXPECT_EQUAL(psk_identity_vec[i].obfuscated_ticket_age, expected_obf_age);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&psk_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
        /* Test failure case when the PSK Identities are not set by the client prior to s2n_client_pre_shared_key_extension.send */
        {
            struct s2n_stuffer psk_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_extension, 0));

            EXPECT_FAILURE(s2n_client_pre_shared_key_extension.send(conn, &psk_extension));

            EXPECT_SUCCESS(s2n_stuffer_free(&psk_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }
    /* Test s2n_client_pre_shared_key_extension.recv */
    {
        /* Test that s2n_client_pre_shared_key_extension receives the selected PSK Identity succesfully */
        {
            struct s2n_stuffer psk_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_extension, 0));

            EXPECT_SUCCESS(s2n_connection_set_client_psk_identities(conn, psk_identity_vec, psk_identity_vlen));

            uint16_t selected_psk_identity_idx = 0;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&psk_extension, selected_psk_identity_idx));
            EXPECT_SUCCESS(s2n_client_pre_shared_key_extension.recv(conn, &psk_extension));
            EXPECT_TRUE(conn->initial.client_psk_config.selected_psk_identity == selected_psk_identity_idx);

            selected_psk_identity_idx = 1;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&psk_extension, selected_psk_identity_idx));
            EXPECT_SUCCESS(s2n_client_pre_shared_key_extension.recv(conn, &psk_extension));
            EXPECT_TRUE(conn->initial.client_psk_config.selected_psk_identity == selected_psk_identity_idx);

            EXPECT_SUCCESS(s2n_stuffer_free(&psk_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
        /* Test failure case when client receives a PSK Identity not within the range sent by the client  */
        {
            struct s2n_stuffer psk_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_extension, 0));

            EXPECT_SUCCESS(s2n_connection_set_client_psk_identities(conn, psk_identity_vec, psk_identity_vlen));

            uint16_t selected_psk_identity_idx = -1;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&psk_extension, selected_psk_identity_idx));
            EXPECT_FAILURE_WITH_ERRNO(s2n_client_pre_shared_key_extension.recv(conn, &psk_extension), S2N_ERR_INVALID_PSK_VECTOR_LEN);
        
            selected_psk_identity_idx = psk_identity_vlen + 1;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&psk_extension, selected_psk_identity_idx));
            EXPECT_FAILURE_WITH_ERRNO(s2n_client_pre_shared_key_extension.recv(conn, &psk_extension), S2N_ERR_INVALID_PSK_VECTOR_LEN);
    
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&psk_extension, selected_psk_identity_idx));
            EXPECT_FAILURE_WITH_ERRNO(s2n_client_pre_shared_key_extension.recv(conn, &psk_extension), S2N_ERR_INVALID_PSK_VECTOR_LEN);

            EXPECT_SUCCESS(s2n_stuffer_free(&psk_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    END_TEST();
    return 0;
}
