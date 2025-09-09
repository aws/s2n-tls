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

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_async_offload.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "utils/s2n_safety.h"

#define S2N_ASYNC_OFFLOAD_OP_NONE 0

struct s2n_async_offload_cb_test {
    unsigned async_test : 1;
    int result;
    int invoked_count;
    struct s2n_async_offload_op *last_seen_op;
};

int s2n_async_offload_test_callback(struct s2n_connection *conn, struct s2n_async_offload_op *op, void *ctx)
{
    EXPECT_NOT_NULL(op);
    struct s2n_async_offload_cb_test *data = (struct s2n_async_offload_cb_test *) ctx;
    data->invoked_count += 1;
    data->last_seen_op = op;

    if (!data->async_test) {
        EXPECT_SUCCESS(s2n_async_offload_op_perform(op));
    }
    return data->result;
}

static int s2n_test_handshake_async(struct s2n_connection *server_conn, struct s2n_connection *client_conn,
        struct s2n_async_offload_cb_test *data)
{
    while (true) {
        int ret_val = s2n_negotiate_test_server_and_client(server_conn, client_conn);

        if (ret_val == 0) {
            break;
        } else if (s2n_errno == S2N_ERR_ASYNC_BLOCKED) {
            /* Handshake remains blocked as long as op_perform() is not invoked. */
            for (int i = 0; i < 3; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                        S2N_ERR_ASYNC_BLOCKED);
            }
            EXPECT_SUCCESS(s2n_async_offload_op_perform(data->last_seen_op));
            /* Each operation can only be performed once. */
            EXPECT_FAILURE_WITH_ERRNO(s2n_async_offload_op_perform(data->last_seen_op), S2N_ERR_INVALID_STATE);
        } else {
            return ret_val;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* Safety Check */
    {
        struct s2n_async_offload_cb_test test_data = { 0 };
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_async_offload_callback(NULL, S2N_ASYNC_OFFLOAD_ALLOW_ALL,
                                          s2n_async_offload_test_callback, &test_data),
                S2N_ERR_NULL);

        DEFER_CLEANUP(struct s2n_config *test_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(test_config);
        EXPECT_EQUAL(test_config->async_offload_allow_list, S2N_ASYNC_OFFLOAD_OP_NONE);
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_async_offload_callback(test_config, S2N_ASYNC_OFFLOAD_ALLOW_ALL,
                                          NULL, &test_data),
                S2N_ERR_NULL);

        EXPECT_SUCCESS(s2n_config_set_async_offload_callback(test_config, S2N_ASYNC_OFFLOAD_PKEY_VERIFY,
                s2n_async_offload_test_callback, &test_data));
        EXPECT_TRUE(s2n_async_offload_is_op_in_allow_list(test_config, S2N_ASYNC_OFFLOAD_PKEY_VERIFY));

        EXPECT_FAILURE_WITH_ERRNO(s2n_async_offload_op_perform(NULL), S2N_ERR_NULL);
        struct s2n_async_offload_op test_op = { 0 };
        EXPECT_FAILURE_WITH_ERRNO(s2n_async_offload_op_perform(&test_op), S2N_ERR_INVALID_STATE);
    }

    /* clang-format off */
    struct {
        bool async_test;
        s2n_async_offload_op_type allow_list;
        int cb_return;
        int cb_invoked;
        bool client_auth;
        s2n_error expected_error;
    } test_cases[] = {
        /* Default option: no op type is allowed. */
        {
            .async_test = false,
            .allow_list = S2N_ASYNC_OFFLOAD_OP_NONE,
            .cb_return = S2N_SUCCESS,
            .cb_invoked = 0,
            .client_auth = true,
            .expected_error = S2N_ERR_OK,
        },
        /* Test a random value that has not been used by any op type. */
        /* Changing return value does not fail the handshake because the callback is not invoked. */
        {
            .async_test = false,
            .allow_list = 0x70000000,
            .cb_return = S2N_FAILURE,
            .cb_invoked = 0,
            .client_auth = true,
            .expected_error = S2N_ERR_OK,
        },
        /* Async PKEY_VERIFY allowed. Client auth enabled. A successful handshake performs pkey_verify() twice. */
        {
            .async_test = false,
            .allow_list = S2N_ASYNC_OFFLOAD_PKEY_VERIFY,
            .cb_return = S2N_SUCCESS,
            .cb_invoked = 2,
            .client_auth = true,
            .expected_error = S2N_ERR_OK,
        },
        /* Any op type is allowed. Handshake failed because the callback failed in the first attempt. */
        {
            .async_test = false,
            .allow_list = S2N_ASYNC_OFFLOAD_ALLOW_ALL,
            .cb_return = S2N_FAILURE,
            .cb_invoked = 1,
            .client_auth = true,
            .expected_error = S2N_ERR_CANCELLED,
        },
        /* Client auth is enabled. pkey_verify() is performed by both server side and client side. */
        {
            .async_test = true,
            .allow_list = S2N_ASYNC_OFFLOAD_PKEY_VERIFY,
            .cb_return = S2N_SUCCESS,
            .cb_invoked = 2,
            .client_auth = true,
            .expected_error = S2N_ERR_ASYNC_BLOCKED,
        },
        /* Client auth is not enabled. pkey_verify() is performed only by client side. */
        {
            .async_test = true,
            .allow_list = S2N_ASYNC_OFFLOAD_ALLOW_ALL,
            .cb_return = S2N_SUCCESS,
            .cb_invoked = 1,
            .client_auth = false,
            .expected_error = S2N_ERR_ASYNC_BLOCKED,
        },
    };
    /* clang-format on */

    /* Test with both TLS 1.2 and TLS 1.3 policies */
    const char *versions[] = { "20240501", "default_tls13" };

    /* Sync Test: 1) op type is not allowed, or 2) op_perform() invoked in the callback. */
    for (int test_idx = 0; test_idx < s2n_array_len(test_cases); test_idx++) {
        for (int version_idx = 0; version_idx < s2n_array_len(versions); version_idx++) {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, versions[version_idx]));
            if (test_cases[test_idx].client_auth) {
                EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED));
            }

            struct s2n_async_offload_cb_test data = {
                .async_test = test_cases[test_idx].async_test,
                .result = test_cases[test_idx].cb_return,
            };
            EXPECT_SUCCESS(s2n_config_set_async_offload_callback(config, test_cases[test_idx].allow_list,
                    s2n_async_offload_test_callback, &data));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            s2n_error expected_error = test_cases[test_idx].expected_error;
            if (test_cases[test_idx].async_test) {
                EXPECT_SUCCESS(s2n_test_handshake_async(server_conn, client_conn, &data));
            } else if (expected_error == S2N_ERR_OK) {
                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            } else {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), expected_error);
            }
            EXPECT_EQUAL(data.invoked_count, test_cases[test_idx].cb_invoked);

            if (s2n_is_tls13_fully_supported() && version_idx == 1) {
                EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server_conn), S2N_TLS13);
            }
        }
    }

    END_TEST();
}
