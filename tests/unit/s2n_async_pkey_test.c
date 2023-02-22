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

#include "tls/s2n_async_pkey.h"

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "utils/s2n_safety.h"

struct s2n_async_pkey_op *pkey_op = NULL;

uint8_t test_digest_data[] = "I hashed this";
const uint32_t test_digest_size = sizeof(test_digest_data);
const uint8_t test_signature_data[] = "I signed this";
const uint32_t test_signature_size = sizeof(test_signature_data);
uint8_t test_encrypted_data[] = "I encrypted this";
const uint32_t test_encrypted_size = sizeof(test_encrypted_data);
uint8_t test_decrypted_data[] = "I decrypted this";
const uint32_t test_decrypted_size = sizeof(test_decrypted_data);

uint8_t offload_callback_count = 0;

typedef int(async_handler)(struct s2n_connection *conn);

/* Declaring a flag to check if sign operation is called at least once for all cipher_suites
 * while performing handshake through handler (async_handler_sign_with_different_pkey_and_apply) */
static bool async_handler_sign_operation_called = false;

static int async_handler_fail(struct s2n_connection *conn)
{
    FAIL_MSG("async_handler_fail should never get invoked");
    return S2N_FAILURE;
}

static int async_handler_wipe_connection_and_apply(struct s2n_connection *conn)
{
    /* Check that we have pkey_op */
    EXPECT_NOT_NULL(pkey_op);

    /* Extract pkey */
    struct s2n_cert_chain_and_key *chain_and_key = s2n_connection_get_selected_cert(conn);
    EXPECT_NOT_NULL(chain_and_key);

    s2n_cert_private_key *pkey = s2n_cert_chain_and_key_get_private_key(chain_and_key);
    EXPECT_NOT_NULL(pkey);

    /* Wipe connection */
    EXPECT_SUCCESS(s2n_connection_wipe(conn));

    /* Test that we can perform pkey operation, even if original connection was wiped */
    EXPECT_SUCCESS(s2n_async_pkey_op_perform(pkey_op, pkey));

    /* Test that pkey op can't be applied to wiped connection */
    EXPECT_FAILURE_WITH_ERRNO(s2n_async_pkey_op_apply(pkey_op, conn), S2N_ERR_ASYNC_WRONG_CONNECTION);

    /* Free the pkey op */
    EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));
    pkey_op = NULL;

    return S2N_FAILURE;
}

static int async_handler_sign_with_different_pkey_and_apply(struct s2n_connection *conn)
{
    /* Check that we have pkey_op */
    EXPECT_NOT_NULL(pkey_op);

    /* Extract pkey */
    struct s2n_cert_chain_and_key *chain_and_key = s2n_connection_get_selected_cert(conn);
    EXPECT_NOT_NULL(chain_and_key);
    s2n_cert_private_key *pkey = s2n_cert_chain_and_key_get_private_key(chain_and_key);
    EXPECT_NOT_NULL(pkey);

    /* Test that we can perform pkey operation */
    EXPECT_SUCCESS(s2n_async_pkey_op_perform(pkey_op, pkey));

    /* Get type for pkey_op */
    s2n_async_pkey_op_type type = { 0 };
    EXPECT_SUCCESS(s2n_async_pkey_op_get_op_type(pkey_op, &type));

    /* Test apply with different certificate chain only for sign operation */
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

        /* Update async_handler_sign_operation_called flag to true */
        async_handler_sign_operation_called = true;
    } else {
        /* Test decrypt operation passes */
        EXPECT_SUCCESS(s2n_async_pkey_op_apply(pkey_op, conn));
    }

    /* Free the pkey op */
    EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));
    pkey_op = NULL;

    return S2N_SUCCESS;
}

static int async_handler_free_pkey_op(struct s2n_connection *conn)
{
    static int function_entered = 0;

    /* Return failure on the second entrance into function so that we drop from try_handshake */
    if (function_entered++ % 2 == 1) {
        return S2N_FAILURE;
    }

    /* Check that we have pkey_op */
    EXPECT_NOT_NULL(pkey_op);

    /* Free the pkey op */
    EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));
    pkey_op = NULL;

    /* Return success so that try_handshake calls s2n_negotiate again */
    return S2N_SUCCESS;
}

static int try_handshake(struct s2n_connection *server_conn, struct s2n_connection *client_conn, async_handler handler)
{
    s2n_blocked_status server_blocked;
    s2n_blocked_status client_blocked;

    int tries = 0;
    do {
        int client_rc = s2n_negotiate(client_conn, &client_blocked);
        if (!(client_rc == 0 || (client_blocked && s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED))) {
            return S2N_FAILURE;
        }

        int server_rc = s2n_negotiate(server_conn, &server_blocked);
        if (!(server_rc == 0 || (server_blocked && s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED))) {
            return S2N_FAILURE;
        }

        if (server_blocked == S2N_BLOCKED_ON_APPLICATION_INPUT) {
            POSIX_GUARD(handler(server_conn));
        }

        EXPECT_NOT_EQUAL(++tries, 5);
    } while (client_blocked || server_blocked);

    POSIX_GUARD(s2n_shutdown_test_server_and_client(server_conn, client_conn));

    return S2N_SUCCESS;
}

int async_pkey_apply_in_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    /* Check that we have op */
    EXPECT_NOT_NULL(op);

    /* Extract pkey */
    struct s2n_cert_chain_and_key *chain_and_key = s2n_connection_get_selected_cert(conn);
    EXPECT_NOT_NULL(chain_and_key);

    s2n_cert_private_key *pkey = s2n_cert_chain_and_key_get_private_key(chain_and_key);
    EXPECT_NOT_NULL(pkey);

    /* Perform the op */
    EXPECT_SUCCESS(s2n_async_pkey_op_perform(op, pkey));

    /* Test that op can be applied inside the callback */
    EXPECT_SUCCESS(s2n_async_pkey_op_apply(op, conn));

    /* Free the op */
    EXPECT_SUCCESS(s2n_async_pkey_op_free(op));

    return S2N_SUCCESS;
}

int async_pkey_store_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    pkey_op = op;
    return S2N_SUCCESS;
}

int async_pkey_signature_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    pkey_op = op;

    s2n_async_pkey_op_type type = { 0 };
    EXPECT_SUCCESS(s2n_async_pkey_op_get_op_type(op, &type));
    EXPECT_EQUAL(type, S2N_ASYNC_SIGN);

    uint8_t expected_size = 0;
    EXPECT_SUCCESS(s2n_hash_digest_size(S2N_HASH_SHA256, &expected_size));

    uint32_t input_size = 0;
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input_size(op, &input_size));
    EXPECT_EQUAL(input_size, expected_size);

    struct s2n_blob input1 = { 0 };
    EXPECT_SUCCESS(s2n_alloc(&input1, input_size));

    struct s2n_blob input2 = { 0 };
    EXPECT_SUCCESS(s2n_alloc(&input2, input_size));

    struct s2n_blob expected_digest = { 0 };
    EXPECT_SUCCESS(s2n_alloc(&expected_digest, expected_size));

    struct s2n_hash_state digest = { 0 };
    EXPECT_SUCCESS(s2n_hash_new(&digest));
    EXPECT_SUCCESS(s2n_hash_init(&digest, S2N_HASH_SHA256));
    EXPECT_SUCCESS(s2n_hash_update(&digest, test_digest_data, test_digest_size));
    EXPECT_SUCCESS(s2n_hash_digest(&digest, expected_digest.data, expected_digest.size));
    EXPECT_SUCCESS(s2n_hash_free(&digest));

    /* Make sure that s2n_async_pkey_op_get_input can be called multiple times, and the returned values are the same. */
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input(op, input1.data, input1.size));
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input(op, input2.data, input2.size));

    EXPECT_EQUAL(input1.size, input2.size);
    EXPECT_BYTEARRAY_EQUAL(input1.data, input2.data, input1.size);
    EXPECT_BYTEARRAY_EQUAL(input1.data, expected_digest.data, expected_size);

    EXPECT_SUCCESS(s2n_free(&input1));
    EXPECT_SUCCESS(s2n_free(&input2));
    EXPECT_SUCCESS(s2n_free(&expected_digest));

    EXPECT_SUCCESS(s2n_async_pkey_op_set_output(op, test_signature_data, test_signature_size));
    offload_callback_count++;

    return S2N_SUCCESS;
}

int async_pkey_decrypt_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    pkey_op = op;

    s2n_async_pkey_op_type type = { 0 };
    EXPECT_SUCCESS(s2n_async_pkey_op_get_op_type(op, &type));
    EXPECT_EQUAL(type, S2N_ASYNC_DECRYPT);

    uint32_t input_size = 0;
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input_size(op, &input_size));
    EXPECT_EQUAL(input_size, test_encrypted_size);

    struct s2n_blob input_buffer1 = { 0 };
    EXPECT_SUCCESS(s2n_alloc(&input_buffer1, input_size));

    struct s2n_blob input_buffer2 = { 0 };
    EXPECT_SUCCESS(s2n_alloc(&input_buffer2, input_size));

    /* Make sure that s2n_async_pkey_op_get_input can be called multiple times, and the returned values are the same. */
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input(op, input_buffer1.data, input_buffer1.size));
    EXPECT_BYTEARRAY_EQUAL(input_buffer1.data, test_encrypted_data, test_encrypted_size);

    EXPECT_SUCCESS(s2n_async_pkey_op_get_input(op, input_buffer2.data, input_buffer2.size));
    EXPECT_BYTEARRAY_EQUAL(input_buffer2.data, test_encrypted_data, test_encrypted_size);

    EXPECT_EQUAL(input_buffer1.size, input_buffer2.size);
    EXPECT_EQUAL(input_buffer1.size, test_encrypted_size);
    EXPECT_BYTEARRAY_EQUAL(input_buffer1.data, input_buffer2.data, test_encrypted_size);

    EXPECT_SUCCESS(s2n_free(&input_buffer1));
    EXPECT_SUCCESS(s2n_free(&input_buffer2));

    EXPECT_SUCCESS(s2n_async_pkey_op_set_output(op, test_decrypted_data, test_decrypted_size));
    offload_callback_count++;

    return S2N_SUCCESS;
}

int s2n_async_sign_complete(struct s2n_connection *conn, struct s2n_blob *signature)
{
    EXPECT_NOT_NULL(conn);
    EXPECT_NOT_NULL(signature);

    EXPECT_EQUAL(signature->size, test_signature_size);
    EXPECT_BYTEARRAY_EQUAL(signature->data, test_signature_data, test_signature_size);
    offload_callback_count++;

    return S2N_SUCCESS;
}

int s2n_async_decrypt_complete(struct s2n_connection *conn, bool rsa_failed, struct s2n_blob *decrypted)
{
    EXPECT_NOT_NULL(conn);
    EXPECT_NOT_NULL(decrypted);
    EXPECT_FALSE(rsa_failed);

    EXPECT_EQUAL(decrypted->size, test_decrypted_size);
    EXPECT_BYTEARRAY_EQUAL(decrypted->data, test_decrypted_data, test_decrypted_size);
    offload_callback_count++;

    return S2N_SUCCESS;
}

int async_pkey_invalid_input_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    pkey_op = op;

    EXPECT_FAILURE(s2n_async_pkey_op_get_op_type(op, NULL));
    EXPECT_FAILURE(s2n_async_pkey_op_get_input_size(op, NULL));
    EXPECT_FAILURE(s2n_async_pkey_op_get_input(op, NULL, 0));

    uint32_t input_size = 0;
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input_size(op, &input_size));

    uint8_t placeholder_buffer[] = { 0x0, 0x0, 0x0, 0x0 };

    /* Buffer too small to contain data. */
    EXPECT_FAILURE(s2n_async_pkey_op_get_input(op, placeholder_buffer, input_size - 1));

    EXPECT_FAILURE(s2n_async_pkey_op_set_output(op, NULL, test_signature_size));
    offload_callback_count++;

    return S2N_FAILURE;
}

int async_pkey_invalid_complete(struct s2n_connection *conn, struct s2n_blob *signature)
{
    FAIL_MSG("Invalid async pkey callback was invoked. The callback should never be invoked if there was an earlier"
             " failure in the async_pkey_op.");
    return S2N_FAILURE;
}

static int s2n_test_bad_sign(const struct s2n_pkey *pub_key, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    /* Just write all zeroes.
     * This could accidentally be the correct signature, but it's very unlikely.
     */
    POSIX_GUARD(s2n_blob_zero(signature));
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    char dhparams_pem[S2N_MAX_TEST_PEM_SIZE];
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    /* Run all tests for 2 cipher suites to test both sign and decrypt operations */
    struct s2n_cipher_suite *test_cipher_suites[] = {
        &s2n_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    };

    for (size_t i = 0; i < s2n_array_len(test_cipher_suites); i++) {
        struct s2n_cipher_preferences server_cipher_preferences = {
            .count = 1,
            .suites = &test_cipher_suites[i],
        };

        struct s2n_security_policy server_security_policy = {
            .minimum_protocol_version = S2N_TLS12,
            .cipher_preferences = &server_cipher_preferences,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &s2n_signature_preferences_20200207,
            .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        EXPECT_TRUE(test_cipher_suites[i]->available);

        TEST_DEBUG_PRINT("Testing %s\n", test_cipher_suites[i]->name);

        /*  Test: apply while invoking callback */
        {
            struct s2n_config *server_config, *client_config;
            EXPECT_NOT_NULL(server_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_apply_in_callback));
            server_config->security_policy = &server_security_policy;

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
            /* Security policy must support all cipher suites in test_cipher_suites above */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all"));

            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            /* Create connection */
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            /* Create nonblocking pipes */
            struct s2n_test_io_pair io_pair;
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_SUCCESS(try_handshake(server_conn, client_conn, async_handler_fail));

            /* Free the data */
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
            EXPECT_SUCCESS(s2n_config_free(server_config));
            EXPECT_SUCCESS(s2n_config_free(client_config));
        }

        /*  Test: wipe connection and then perform and apply pkey op */
        {
            struct s2n_config *server_config, *client_config;
            EXPECT_NOT_NULL(server_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_store_callback));
            server_config->security_policy = &server_security_policy;

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
            /* Security policy must support all cipher suites in test_cipher_suites above */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all"));

            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            /* Create connection */
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            /* Create nonblocking pipes */
            struct s2n_test_io_pair io_pair;
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_EQUAL(try_handshake(server_conn, client_conn, async_handler_wipe_connection_and_apply), S2N_FAILURE);

            /* Free the data */
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
            EXPECT_SUCCESS(s2n_config_free(server_config));
            EXPECT_SUCCESS(s2n_config_free(client_config));
        }

        /*  Test: free the pkey op and try s2n_negotiate again */
        {
            struct s2n_config *server_config, *client_config;
            EXPECT_NOT_NULL(server_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_store_callback));
            server_config->security_policy = &server_security_policy;

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
            /* Security policy must support all cipher suites in test_cipher_suites above */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all"));

            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            /* Create connection */
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            /* Create nonblocking pipes */
            struct s2n_test_io_pair io_pair;
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_FAILURE_WITH_ERRNO(
                    try_handshake(server_conn, client_conn, async_handler_free_pkey_op), S2N_ERR_ASYNC_BLOCKED);

            /* Free the data */
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
            EXPECT_SUCCESS(s2n_config_free(server_config));
            EXPECT_SUCCESS(s2n_config_free(client_config));
        }

        /* Test: Apply invalid signature */
        {
            struct s2n_config *server_config, *client_config;
            EXPECT_NOT_NULL(server_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_store_callback));
            server_config->security_policy = &server_security_policy;
            /* Enable signature validation for async sign call */
            EXPECT_SUCCESS(s2n_config_set_async_pkey_validation_mode(server_config, S2N_ASYNC_PKEY_VALIDATION_STRICT));

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
            /* Security policy must support all cipher suites in test_cipher_suites above */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all"));

            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            /* Create connection */
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            /* Create nonblocking pipes */
            struct s2n_test_io_pair io_pair;
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_SUCCESS(try_handshake(server_conn, client_conn, async_handler_sign_with_different_pkey_and_apply));

            /* Free the data */
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
            EXPECT_SUCCESS(s2n_config_free(server_config));
            EXPECT_SUCCESS(s2n_config_free(client_config));
        }

        /* Test: Apply invalid signature, when signature validation is enabled for all sync / async signatures */
        {
            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(server_config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_store_callback));
            server_config->security_policy = &server_security_policy;

            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(client_config);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
            /* Security policy must support all cipher suites in test_cipher_suites above */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all"));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            /* Create connection */
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            /* Create nonblocking pipes */
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            /* Enable signature validation */
            EXPECT_SUCCESS(s2n_config_set_verify_after_sign(server_config, S2N_VERIFY_AFTER_SIGN_ENABLED));
            EXPECT_SUCCESS(try_handshake(server_conn, client_conn, async_handler_sign_with_different_pkey_and_apply));
        }
    }

    /* Test if sign operation was called at least once for 'Test: Apply invalid signature',
     * the flag holds the value after executing handshakes for all cipher_suites */
    EXPECT_EQUAL(async_handler_sign_operation_called, true);

    DEFER_CLEANUP(struct s2n_hash_state digest = { 0 }, s2n_hash_free);
    EXPECT_SUCCESS(s2n_hash_new(&digest));
    EXPECT_SUCCESS(s2n_hash_init(&digest, S2N_HASH_SHA256));
    EXPECT_SUCCESS(s2n_hash_update(&digest, test_digest_data, test_digest_size));

    /* Test: signature offload. */
    {
        EXPECT_EQUAL(0, offload_callback_count);
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        conn->config->async_pkey_cb = async_pkey_signature_callback;

        EXPECT_FALSE(s2n_result_is_ok(s2n_async_pkey_sign(conn, S2N_SIGNATURE_ECDSA, &digest, s2n_async_sign_complete)));
        EXPECT_TRUE(s2n_errno == S2N_ERR_ASYNC_BLOCKED);
        EXPECT_EQUAL(1, offload_callback_count);

        EXPECT_SUCCESS(s2n_async_pkey_op_apply(pkey_op, conn));
        EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));
        EXPECT_EQUAL(2, offload_callback_count);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: decrypt offload. */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        conn->config->async_pkey_cb = async_pkey_decrypt_callback;

        struct s2n_blob encrypted_data = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&encrypted_data, test_encrypted_data, test_encrypted_size));

        struct s2n_blob decrypted_data = { 0 };
        /* Re-use the encrypted data buffer to make sure that the data was actually transformed in the callback. 
         * If we filled this with the decrypted data, we would not know if the decryption happened in the callback. */
        EXPECT_SUCCESS(s2n_blob_init(&decrypted_data, test_encrypted_data, test_encrypted_size));

        EXPECT_FALSE(s2n_result_is_ok(s2n_async_pkey_decrypt(conn, &encrypted_data, &decrypted_data, s2n_async_decrypt_complete)));
        EXPECT_TRUE(s2n_errno == S2N_ERR_ASYNC_BLOCKED);
        EXPECT_EQUAL(3, offload_callback_count);

        EXPECT_SUCCESS(s2n_async_pkey_op_apply(pkey_op, conn));
        EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));
        EXPECT_EQUAL(4, offload_callback_count);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: errors in callback. */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        conn->config->async_pkey_cb = async_pkey_invalid_input_callback;

        EXPECT_FALSE(s2n_result_is_ok(s2n_async_pkey_sign(conn, S2N_SIGNATURE_ECDSA, &digest, async_pkey_invalid_complete)));
        EXPECT_TRUE(s2n_errno == S2N_ERR_ASYNC_CALLBACK_FAILED);
        EXPECT_EQUAL(5, offload_callback_count);

        EXPECT_FAILURE(s2n_async_pkey_op_apply(pkey_op, conn));
        EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));
        EXPECT_EQUAL(5, offload_callback_count);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    EXPECT_SUCCESS(s2n_reset_tls13_in_test());

    /* Test: Apply invalid signature to sync operation */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_chain_and_key));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Start the handshake.
         * We need to perform enough of the handshake to choose a certificate / private key.
         */
        EXPECT_SUCCESS(s2n_config_set_verify_after_sign(config, S2N_VERIFY_AFTER_SIGN_ENABLED));
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_CERT));

        /* Setup the pkey verify operation to fail for the chosen private key */
        EXPECT_NOT_NULL(server_conn->handshake_params.our_chain_and_key);
        EXPECT_NOT_NULL(server_conn->handshake_params.our_chain_and_key->private_key);
        struct s2n_pkey *original_pkey = server_conn->handshake_params.our_chain_and_key->private_key;
        struct s2n_pkey bad_pkey = *original_pkey;
        bad_pkey.sign = s2n_test_bad_sign;
        server_conn->handshake_params.our_chain_and_key->private_key = &bad_pkey;

        /* Verify after sign should fail */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_SUCCESS(s2n_config_set_verify_after_sign(config, S2N_VERIFY_AFTER_SIGN_ENABLED));
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_VERIFY_SIGNATURE);

        /* Reset pkey for cleanup */
        server_conn->handshake_params.our_chain_and_key->private_key = original_pkey;
    }

    END_TEST();
}
