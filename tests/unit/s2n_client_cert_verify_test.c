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

#include <stdint.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_async_pkey.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

static bool async_callback_invoked = false;
static bool async_sign_operation_called_s2n_client = false;
static struct s2n_async_pkey_op *pkey_op = NULL;
static struct s2n_connection *pkey_conn = NULL;

const uint8_t test_signature_data[] = "I signed this";
const uint32_t test_signature_size = sizeof(test_signature_data);
const uint32_t test_max_signature_size = 2 * sizeof(test_signature_data);

typedef int(async_handler)(struct s2n_connection *conn, s2n_blocked_status *block);

static S2N_RESULT test_size(const struct s2n_pkey *pkey, uint32_t *size_out)
{
    *size_out = test_max_signature_size;
    return S2N_RESULT_OK;
}

static int test_sign(const struct s2n_pkey *priv_key, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    POSIX_CHECKED_MEMCPY(signature->data, test_signature_data, test_signature_size);
    signature->size = test_signature_size;
    return S2N_SUCCESS;
}

int s2n_async_pkey_store_op(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    EXPECT_NOT_NULL(conn);
    EXPECT_NOT_NULL(op);

    async_callback_invoked = true;
    pkey_op = op;
    pkey_conn = conn;

    return S2N_SUCCESS;
}

static int s2n_test_negotiate_with_async_pkey_op_handler(struct s2n_connection *conn, s2n_blocked_status *block)
{
    int rc = s2n_negotiate(conn, block);
    if (!(rc == 0 || (*block && s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED))) {
        return S2N_FAILURE;
    }

    if (*block == S2N_BLOCKED_ON_APPLICATION_INPUT && pkey_op != NULL) {
        struct s2n_cert_chain_and_key *chain_and_key = s2n_connection_get_selected_cert(pkey_conn);
        EXPECT_NOT_NULL(chain_and_key);

        s2n_cert_private_key *pkey = s2n_cert_chain_and_key_get_private_key(chain_and_key);
        EXPECT_NOT_NULL(pkey);

        EXPECT_SUCCESS(s2n_async_pkey_op_perform(pkey_op, pkey));
        EXPECT_SUCCESS(s2n_async_pkey_op_apply(pkey_op, conn));
        EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));
        pkey_op = NULL;
        pkey_conn = NULL;
    }

    return S2N_SUCCESS;
}

static int s2n_test_apply_with_invalid_signature_handler(struct s2n_connection *conn, s2n_blocked_status *block)
{
    int rc = s2n_negotiate(conn, block);
    if (!(rc == 0 || (*block && s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED))) {
        return S2N_FAILURE;
    }

    if (*block == S2N_BLOCKED_ON_APPLICATION_INPUT && pkey_op != NULL) {
        struct s2n_cert_chain_and_key *chain_and_key = s2n_connection_get_selected_cert(pkey_conn);
        EXPECT_NOT_NULL(chain_and_key);

        s2n_cert_private_key *pkey = s2n_cert_chain_and_key_get_private_key(chain_and_key);
        EXPECT_NOT_NULL(pkey);

        EXPECT_SUCCESS(s2n_async_pkey_op_perform(pkey_op, pkey));

        /* Get type for pkey_op */
        s2n_async_pkey_op_type type = { 0 };
        EXPECT_SUCCESS(s2n_async_pkey_op_get_op_type(pkey_op, &type));

        /* Test if signature with wrong private key fails at verification when apply */
        if (type == S2N_ASYNC_SIGN) {
            /* Create new chain and key, and modify current server conn */
            struct s2n_cert_chain_and_key *chain_and_key_2 = NULL;
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key_2,
                    S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

            /* Change server conn cert data */
            EXPECT_NOT_NULL(conn->handshake_params.our_chain_and_key);
            conn->handshake_params.our_chain_and_key = chain_and_key_2;

            /* Test that async sign operation will fail as signature was performed over different private key */
            EXPECT_FAILURE_WITH_ERRNO(s2n_async_pkey_op_apply(pkey_op, conn), S2N_ERR_VERIFY_SIGNATURE);

            /* Set pkey_op's validation mode to S2N_ASYNC_PKEY_VALIDATION_FAST and test that async sign apply will pass now */
            EXPECT_SUCCESS(s2n_async_pkey_op_set_validation_mode(pkey_op, S2N_ASYNC_PKEY_VALIDATION_FAST));
            EXPECT_SUCCESS(s2n_async_pkey_op_apply(pkey_op, conn));

            /* Set chain_and_key back to original value and free new chain_and_key */
            conn->handshake_params.our_chain_and_key = chain_and_key;
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key_2));

            /* Set flag to test if sign operation called for S2N_CLIENT */
            if (conn->mode == S2N_CLIENT) {
                async_sign_operation_called_s2n_client = true;
            }
        } else {
            EXPECT_SUCCESS(s2n_async_pkey_op_apply(pkey_op, conn));
        }

        EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));
        pkey_op = NULL;
        pkey_conn = NULL;
    }

    return S2N_SUCCESS;
}

static int s2n_try_handshake_with_async_pkey_op(struct s2n_connection *server_conn, struct s2n_connection *client_conn,
        async_handler handler)
{
    s2n_blocked_status server_blocked = { 0 };
    s2n_blocked_status client_blocked = { 0 };

    do {
        EXPECT_SUCCESS(handler(client_conn, &client_blocked));
        EXPECT_SUCCESS(handler(server_conn, &server_blocked));
    } while (client_blocked || server_blocked);

    POSIX_GUARD(s2n_shutdown_test_server_and_client(server_conn, client_conn));

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test that the signature size is written correctly when not equal to the maximum */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        /* Set any signature scheme. Our test pkey methods ignore it. */
        conn->handshake_params.client_cert_sig_scheme = &s2n_rsa_pkcs1_md5_sha1;

        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        chain_and_key->private_key->size = test_size;
        chain_and_key->private_key->sign = test_sign;
        conn->handshake_params.our_chain_and_key = chain_and_key;

        EXPECT_SUCCESS(s2n_client_cert_verify_send(conn));

        uint16_t signature_scheme_iana;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&conn->handshake.io, &signature_scheme_iana));
        EXPECT_EQUAL(signature_scheme_iana, s2n_rsa_pkcs1_md5_sha1.iana_value);

        uint16_t signature_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&conn->handshake.io, &signature_size));
        EXPECT_NOT_EQUAL(signature_size, test_max_signature_size);
        EXPECT_EQUAL(signature_size, test_signature_size);
        EXPECT_EQUAL(signature_size, s2n_stuffer_data_available(&conn->handshake.io));

        uint8_t *signature_data = s2n_stuffer_raw_read(&conn->handshake.io, test_signature_size);
        EXPECT_NOT_NULL(signature_data);
        EXPECT_BYTEARRAY_EQUAL(signature_data, test_signature_data, test_signature_size);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    };

    /*  Test: async private key operations. */
    {
        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(client_config, s2n_async_pkey_store_op));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
        /* This cipher preference is set to avoid TLS 1.3. */
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20170210"));
        /* Enable signature validation to test S2N_CLIENT connection signature for async sign operation */
        EXPECT_SUCCESS(s2n_config_set_async_pkey_validation_mode(client_config, S2N_ASYNC_PKEY_VALIDATION_STRICT));

        /* Create connection */
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_REQUIRED));

        struct s2n_config *server_config;
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(server_config));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_REQUIRED));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_try_handshake_with_async_pkey_op(server_conn, client_conn,
                s2n_test_negotiate_with_async_pkey_op_handler));

        /* Make sure async callback was used during the handshake. */
        EXPECT_TRUE(async_callback_invoked);

        /* Verify that both connections negotiated Mutual Auth */
        EXPECT_TRUE(s2n_connection_client_cert_used(server_conn));
        EXPECT_TRUE(s2n_connection_client_cert_used(client_conn));
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

        /* Free the data */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    };

    /* Test: Apply with invalid signature */
    {
        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(client_config, s2n_async_pkey_store_op));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20170210"));
        /* Enable signature validation to test S2N_CLIENT connection signature for async sign operation */
        EXPECT_SUCCESS(s2n_config_set_async_pkey_validation_mode(client_config, S2N_ASYNC_PKEY_VALIDATION_STRICT));

        /* Create connection */
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_REQUIRED));

        struct s2n_config *server_config;
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(server_config));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_REQUIRED));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_try_handshake_with_async_pkey_op(server_conn, client_conn,
                s2n_test_apply_with_invalid_signature_handler));

        /* Make sure async callback was used during the handshake. */
        EXPECT_TRUE(async_callback_invoked);

        /* Make sure async sign operation was called at least once for S2N_CLIENT */
        EXPECT_TRUE(async_sign_operation_called_s2n_client);

        /* Verify that both connections negotiated Mutual Auth */
        EXPECT_TRUE(s2n_connection_client_cert_used(server_conn));
        EXPECT_TRUE(s2n_connection_client_cert_used(client_conn));
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

        /* Free the data */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    };

    END_TEST();
}
