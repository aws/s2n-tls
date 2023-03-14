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
#include "tls/extensions/s2n_server_sct_list.h"

const uint8_t sct_list_data[] = "SCT LIST DATA";

int s2n_test_enable_sending_extension(struct s2n_connection *conn, struct s2n_cert_chain_and_key *chain_and_key)
{
    conn->mode = S2N_SERVER;
    conn->ct_level_requested = S2N_CT_SUPPORT_REQUEST;
    conn->handshake_params.our_chain_and_key = chain_and_key;
    EXPECT_SUCCESS(s2n_cert_chain_and_key_set_sct_list(chain_and_key, sct_list_data, s2n_array_len(sct_list_data)));
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* should_send */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Don't send by default */
        EXPECT_FALSE(s2n_server_sct_list_extension.should_send(conn));

        /* Send if all prerequisites met */
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));
        EXPECT_TRUE(s2n_server_sct_list_extension.should_send(conn));

        /* Don't send if client */
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));
        conn->mode = S2N_CLIENT;
        EXPECT_FALSE(s2n_server_sct_list_extension.should_send(conn));

        /* Don't send if certificate transparency not requested */
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));
        conn->ct_level_requested = S2N_CT_SUPPORT_NONE;
        EXPECT_FALSE(s2n_server_sct_list_extension.should_send(conn));

        /* Don't send if no certificate set */
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));
        conn->handshake_params.our_chain_and_key = NULL;
        EXPECT_FALSE(s2n_server_sct_list_extension.should_send(conn));

        /* Don't send if no ocsp data */
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));
        EXPECT_SUCCESS(s2n_free(&conn->handshake_params.our_chain_and_key->sct_list));
        EXPECT_FALSE(s2n_server_sct_list_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_server_sct_list_extension.send(conn, &stuffer));

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), s2n_array_len(sct_list_data));
        EXPECT_BYTEARRAY_EQUAL(stuffer.blob.data, sct_list_data, s2n_array_len(sct_list_data));

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test recv */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_test_enable_sending_extension(conn, chain_and_key));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_server_sct_list_extension.send(conn, &stuffer));

        EXPECT_EQUAL(conn->ct_response.size, 0);
        EXPECT_SUCCESS(s2n_server_sct_list_extension.recv(conn, &stuffer));
        EXPECT_EQUAL(conn->ct_response.size, s2n_array_len(sct_list_data));
        EXPECT_BYTEARRAY_EQUAL(conn->ct_response.data, sct_list_data, s2n_array_len(sct_list_data));

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    END_TEST();
    return 0;
}
