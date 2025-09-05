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

struct s2n_async_offload_cb_test {
    unsigned invoke_perform : 1;
    int result;

    int invoked_count;
    struct s2n_async_op *op;
};

int s2n_async_offload_test_callback(struct s2n_connection *conn, struct s2n_async_op *op, void *ctx)
{
    EXPECT_NOT_NULL(op);

    struct s2n_async_offload_cb_test *data = (struct s2n_async_offload_cb_test *) ctx;
    data->invoked_count += 1;
    data->op = op;

    if (data->invoke_perform) {
        EXPECT_SUCCESS(s2n_async_op_perform(op));
    }

    return data->result;
}

static int s2n_test_handshake_async(struct s2n_connection *server_conn, struct s2n_connection *client_conn,
        struct s2n_async_offload_cb_test *data)
{
    while (true) {
        int ret_val = s2n_negotiate_test_server_and_client(server_conn, client_conn);

        if (s2n_errno == S2N_ERR_ASYNC_BLOCKED) {
            /* Handshake remains blocked as long as op_perform() is not invoked. */
            for (int i = 0; i < 3; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                        S2N_ERR_ASYNC_BLOCKED);
            }

            EXPECT_SUCCESS(s2n_async_op_perform(data->op));
            /* Each operation can only be performed once. */
            EXPECT_FAILURE_WITH_ERRNO(s2n_async_op_perform(data->op), S2N_ERR_INVALID_STATE);
        } else {
            return ret_val;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    /* Safety Check */
    {
        struct s2n_async_offload_cb_test test_data = { 0 };
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_async_offload_callback(NULL, s2n_async_offload_test_callback, S2N_ASYNC_ALLOW_ALL, &test_data),
                S2N_ERR_NULL);

        DEFER_CLEANUP(struct s2n_config *test_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(test_config);
        EXPECT_EQUAL(test_config->async_offload_allow_list, S2N_ASYNC_OP_NONE);
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_async_offload_callback(test_config, NULL, S2N_ASYNC_ALLOW_ALL, &test_data),
                S2N_ERR_NULL);

        EXPECT_SUCCESS(s2n_config_set_async_offload_callback(test_config, s2n_async_offload_test_callback,
                S2N_ASYNC_PKEY_VERIFY, &test_data));
        EXPECT_TRUE(s2n_async_is_op_in_allow_list(test_config, S2N_ASYNC_PKEY_VERIFY));

        EXPECT_FAILURE_WITH_ERRNO(s2n_async_op_perform(NULL), S2N_ERR_NULL);
        struct s2n_async_op test_op = { 0 };
        EXPECT_FAILURE_WITH_ERRNO(s2n_async_op_perform(&test_op), S2N_ERR_INVALID_STATE);
    }

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* clang-format off */
    struct {
        s2n_async_op_type allow_list;
        int cb_return;
        int cb_invoked;
        s2n_error expected_error;
    } sync_tests[] = {
        /* Default option: no op type is allowed. */
        {
            .allow_list = S2N_ASYNC_OP_NONE,
            .cb_return = S2N_SUCCESS,
            .cb_invoked = 0,
            .expected_error = S2N_ERR_OK,
        },
        /* Test a random value that has not been used by any op type. */
        /* Changing return value does not fail the handshake because the callback is not invoked. */
        {
            .allow_list = 0x1000,
            .cb_return = S2N_FAILURE,
            .cb_invoked = 0,
            .expected_error = S2N_ERR_OK,
        },
        /* ASYNC_PKEY_VERIFY is allowed. Client auth is enabled for all the sync tests. */
        /* In this case, a successfule handshake performs pkey_verify() twice. */
        {
            .allow_list = S2N_ASYNC_PKEY_VERIFY,
            .cb_return = S2N_SUCCESS,
            .cb_invoked = 2,
            .expected_error = S2N_ERR_OK,
        },
        /* Any op type is allowed. Handshake failed because the callback failed in the first attempt. */
        {
            .allow_list = S2N_ASYNC_ALLOW_ALL,
            .cb_return = S2N_FAILURE,
            .cb_invoked = 1,
            .expected_error = S2N_ERR_CANCELLED,
        },
    };
    /* clang-format on */

    /* Test with both TLS 1.2 and TLS 1.3 policies */
    const char *versions[] = { "20240501", "default_tls13" };

    /* Sync Test: 1) op type is not allowed, or 2) op_perform() invoked in the callback. */
    for (int test_idx = 0; test_idx < s2n_array_len(sync_tests); test_idx++) {
        for (int version_idx = 0; version_idx < s2n_array_len(versions); version_idx++) {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, versions[version_idx]));
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED));

            struct s2n_async_offload_cb_test data = { .invoke_perform = true, .result = sync_tests[test_idx].cb_return };
            EXPECT_SUCCESS(s2n_config_set_async_offload_callback(config, s2n_async_offload_test_callback,
                    sync_tests[test_idx].allow_list, &data));

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

            s2n_error expected_error = sync_tests[test_idx].expected_error;
            if (expected_error == S2N_ERR_OK) {
                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            } else {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), expected_error);
            }

            EXPECT_EQUAL(data.invoked_count, sync_tests[test_idx].cb_invoked);
        }
    }

    /* clang-format off */
    struct {
        s2n_async_op_type allow_list;
        bool client_auth;
        int cb_invoked;
    } async_tests[] = {
        /* Client auth is enabled. pkey_verify() is performed by both server side and client side. */
        {
            .allow_list = S2N_ASYNC_PKEY_VERIFY,
            .client_auth = true,
            .cb_invoked = 2,
        },
        /* Client auth is not enabled. pkey_verify() is performed only by client side. */
        {
            .allow_list = S2N_ASYNC_ALLOW_ALL,
            .client_auth = false,
            .cb_invoked = 1,
        },
    };
    /* clang-format on */

    /* Async verify test: ASYNC_PKEY_VERIFY is allowed, and op_perform() invoked outside the callback. */
    for (int test_idx = 0; test_idx < s2n_array_len(async_tests); test_idx++) {
        for (int version_idx = 0; version_idx < s2n_array_len(versions); version_idx++) {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, versions[version_idx]));
            if (async_tests[test_idx].client_auth) {
                EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED));
            }

            struct s2n_async_offload_cb_test data = { .invoke_perform = false, .result = S2N_SUCCESS };
            EXPECT_SUCCESS(s2n_config_set_async_offload_callback(config, s2n_async_offload_test_callback,
                    async_tests[test_idx].allow_list, &data));

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

            EXPECT_SUCCESS(s2n_test_handshake_async(server_conn, client_conn, &data));
            EXPECT_EQUAL(data.invoked_count, async_tests[test_idx].cb_invoked);
        }
    }

    END_TEST();
}
