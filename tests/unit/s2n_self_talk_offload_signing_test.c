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

#include "crypto/s2n_rsa_signing.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#define S2N_TEST_CERT_MEM 5000

int s2n_ecdsa_sign_digest(const struct s2n_pkey *priv, struct s2n_blob *digest, struct s2n_blob *signature);
int s2n_rsa_pkcs1v15_sign_digest(const struct s2n_pkey *priv, s2n_hash_algorithm hash_alg,
        struct s2n_blob *digest, struct s2n_blob *signature);
int s2n_rsa_pss_sign_digest(const struct s2n_pkey *priv, s2n_hash_algorithm hash_alg,
        struct s2n_blob *digest_in, struct s2n_blob *signature_out);

struct s2n_async_pkey_op *pkey_op = NULL;
struct s2n_connection *pkey_op_conn = NULL;
static int s2n_test_async_pkey_cb(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    pkey_op = op;
    pkey_op_conn = conn;
    return S2N_SUCCESS;
}

static S2N_RESULT s2n_async_pkey_sign(struct s2n_cert_chain_and_key *complete_chain)
{
    RESULT_ENSURE_REF(pkey_op);
    RESULT_ENSURE_REF(pkey_op_conn);
    RESULT_ENSURE_REF(complete_chain);

    /* Get input */
    uint32_t input_len = 0;
    DEFER_CLEANUP(struct s2n_blob input = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_async_pkey_op_get_input_size(pkey_op, &input_len));
    RESULT_GUARD_POSIX(s2n_realloc(&input, input_len));
    RESULT_GUARD_POSIX(s2n_async_pkey_op_get_input(pkey_op, input.data, input.size));

    /* Setup output */
    uint32_t output_len = 0;
    DEFER_CLEANUP(struct s2n_blob output = { 0 }, s2n_free);
    RESULT_GUARD(s2n_pkey_size(complete_chain->private_key, &output_len));
    RESULT_GUARD_POSIX(s2n_realloc(&output, output_len));

    /* Get signature algorithm */
    s2n_tls_signature_algorithm sig_alg = 0;
    const struct s2n_signature_scheme *sig_scheme = NULL;
    if (pkey_op_conn->mode == S2N_CLIENT) {
        RESULT_GUARD_POSIX(s2n_connection_get_selected_client_cert_signature_algorithm(pkey_op_conn, &sig_alg));
        sig_scheme = pkey_op_conn->handshake_params.client_cert_sig_scheme;
    } else {
        RESULT_GUARD_POSIX(s2n_connection_get_selected_signature_algorithm(pkey_op_conn, &sig_alg));
        sig_scheme = pkey_op_conn->handshake_params.server_cert_sig_scheme;
    }

    /* These are our "external" / "offloaded" operations.
     * Customer use cases will call into a separate library / API, like PCKS11.
     * But for this test we're just going to continue using our own methods.
     */
    s2n_async_pkey_op_type op_type = 0;
    RESULT_GUARD_POSIX(s2n_async_pkey_op_get_op_type(pkey_op, &op_type));
    if (op_type == S2N_ASYNC_DECRYPT) {
        output.size = S2N_TLS_SECRET_LEN;
        RESULT_GUARD_POSIX(s2n_pkey_decrypt(complete_chain->private_key, &input, &output));
    } else if (sig_alg == S2N_TLS_SIGNATURE_ECDSA) {
        RESULT_GUARD_POSIX(s2n_ecdsa_sign_digest(complete_chain->private_key, &input, &output));
    } else if (sig_alg == S2N_TLS_SIGNATURE_RSA) {
        RESULT_GUARD_POSIX(s2n_rsa_pkcs1v15_sign_digest(
                complete_chain->private_key, sig_scheme->hash_alg, &input, &output));
    } else if (sig_alg == S2N_TLS_SIGNATURE_RSA_PSS_RSAE) {
        RESULT_GUARD_POSIX(s2n_rsa_pss_sign_digest(
                complete_chain->private_key, sig_scheme->hash_alg, &input, &output));
    } else {
        RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
    }

    /* Complete async_op */
    RESULT_GUARD_POSIX(s2n_async_pkey_op_set_output(pkey_op, output.data, output.size));
    RESULT_GUARD_POSIX(s2n_async_pkey_op_apply(pkey_op, pkey_op_conn));
    RESULT_GUARD_POSIX(s2n_async_pkey_op_free(pkey_op));
    pkey_op = NULL;
    pkey_op_conn = NULL;

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_do_test_handshake(struct s2n_config *config, struct s2n_cert_chain_and_key *complete_chain,
        uint8_t expected_protocol_version, uint32_t expected_handshake_type)
{
    struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
    RESULT_ENSURE_REF(client_conn);
    RESULT_GUARD_POSIX(s2n_connection_set_config(client_conn, config));

    struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
    RESULT_ENSURE_REF(server_conn);
    RESULT_GUARD_POSIX(s2n_connection_set_config(server_conn, config));

    struct s2n_test_io_pair io_pair = { 0 };
    RESULT_GUARD_POSIX(s2n_io_pair_init_non_blocking(&io_pair));
    RESULT_GUARD_POSIX(s2n_connection_set_io_pair(client_conn, &io_pair));
    RESULT_GUARD_POSIX(s2n_connection_set_io_pair(server_conn, &io_pair));

    while (s2n_negotiate_test_server_and_client(server_conn, client_conn) != S2N_SUCCESS) {
        EXPECT_EQUAL(s2n_errno, S2N_ERR_ASYNC_BLOCKED);
        RESULT_GUARD(s2n_async_pkey_sign(complete_chain));
    }

    RESULT_ENSURE_EQ(client_conn->actual_protocol_version, expected_protocol_version);
    RESULT_ENSURE_EQ(server_conn->actual_protocol_version, expected_protocol_version);
    RESULT_ENSURE_EQ(client_conn->handshake.handshake_type, expected_handshake_type);
    RESULT_ENSURE_EQ(server_conn->handshake.handshake_type, expected_handshake_type);

    RESULT_GUARD_POSIX(s2n_connection_free(server_conn));
    RESULT_GUARD_POSIX(s2n_connection_free(client_conn));
    RESULT_GUARD_POSIX(s2n_io_pair_close(&io_pair));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    uint32_t pem_len = 0;
    uint8_t pem[S2N_TEST_CERT_MEM] = { 0 };

    const char *tls12_policy = "ELBSecurityPolicy-2016-08";
    const char *tls13_policy = "default_tls13";

    /* Some TLS1.2 cipher suites use RSA for key exchange.
     * Doing so requires generating a random key and encrypting it with RSA,
     * which uses the private RSA key for a S2N_ASYNC_DECRYPT operation.
     */
    const char *tls12_rsa_kex_policy = "test_all_rsa_kex";

    uint32_t basic_handshake = NEGOTIATED | FULL_HANDSHAKE;
    uint32_t tls_13_handshake = (basic_handshake | MIDDLEBOX_COMPAT);
    uint32_t tls_12_handshake = (basic_handshake | TLS12_PERFECT_FORWARD_SECRECY);
    uint32_t expected_handshake_with_tls13_policy = s2n_is_tls13_fully_supported() ? tls_13_handshake : tls_12_handshake;

    /* Create cert chains with both a public and private key.
     * We need these to do the actual signing / decrypting once our callback triggers,
     * but they are never passed to the connection or used in the handshake directly.
     */

    struct s2n_cert_chain_and_key *ecdsa_complete_chain = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_complete_chain,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    struct s2n_cert_chain_and_key *rsa_complete_chain = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_complete_chain,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* Create cert chains with only public certificates.
     * These are passed to the connections for use in the handshake.
     */

    struct s2n_cert_chain_and_key *ecdsa_cert_only_chain = s2n_cert_chain_and_key_new();
    EXPECT_NOT_NULL(ecdsa_cert_only_chain);
    EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, pem, &pem_len, sizeof(pem)));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_public_pem_bytes(ecdsa_cert_only_chain, pem, pem_len));

    struct s2n_cert_chain_and_key *rsa_cert_only_chain = s2n_cert_chain_and_key_new();
    EXPECT_NOT_NULL(rsa_cert_only_chain);
    EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_DEFAULT_TEST_CERT_CHAIN, pem, &pem_len, sizeof(pem)));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_public_pem_bytes(rsa_cert_only_chain, pem, pem_len));

    /* ECDSA */
    {
        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_cert_only_chain));
        EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(config, s2n_test_async_pkey_cb));

        /* Basic handshake. Only the server signs. */
        {
            /* Test: TLS1.2 + ECDSA */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, tls12_policy));
            EXPECT_OK(s2n_do_test_handshake(config, ecdsa_complete_chain,
                    S2N_TLS12, basic_handshake | TLS12_PERFECT_FORWARD_SECRECY));

            /* Test: TLS1.3 + ECDSA */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, tls13_policy));
            EXPECT_OK(s2n_do_test_handshake(config, ecdsa_complete_chain,
                    s2n_get_highest_fully_supported_tls_version(), expected_handshake_with_tls13_policy));
        };

        /* Handshake with mutual auth. Both the client and server sign. */
        {
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED));

            /* Test: TLS1.2 + ECDSA + client auth */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, tls12_policy));
            EXPECT_OK(s2n_do_test_handshake(config, ecdsa_complete_chain,
                    S2N_TLS12, basic_handshake | CLIENT_AUTH | TLS12_PERFECT_FORWARD_SECRECY));

            /* Test: TLS1.3 + ECDSA + client auth */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, tls13_policy));
            EXPECT_OK(s2n_do_test_handshake(config, ecdsa_complete_chain,
                    s2n_get_highest_fully_supported_tls_version(), expected_handshake_with_tls13_policy | CLIENT_AUTH));
        };

        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* RSA */
    {
        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, rsa_cert_only_chain));
        EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(config, s2n_test_async_pkey_cb));

        /* Basic handshake. Only the server signs. */
        {
            /* Test: TLS1.2 + RSA kex */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, tls12_rsa_kex_policy));
            EXPECT_OK(s2n_do_test_handshake(config, rsa_complete_chain,
                    S2N_TLS12, basic_handshake));

            /* Test: TLS1.2 + RSA */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, tls12_policy));
            EXPECT_OK(s2n_do_test_handshake(config, rsa_complete_chain,
                    S2N_TLS12, basic_handshake | TLS12_PERFECT_FORWARD_SECRECY));

            /* Test: TLS1.3 + RSA */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, tls13_policy));
            EXPECT_OK(s2n_do_test_handshake(config, rsa_complete_chain,
                    s2n_get_highest_fully_supported_tls_version(), expected_handshake_with_tls13_policy));
        };

        /* Handshake with mutual auth. Both the client and server sign. */
        {
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED));

            /* Test: TLS1.2 + RSA kex + client auth */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, tls12_rsa_kex_policy));
            EXPECT_OK(s2n_do_test_handshake(config, rsa_complete_chain,
                    S2N_TLS12, basic_handshake | CLIENT_AUTH));

            /* Test: TLS1.2 + RSA + client auth */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, tls12_policy));
            EXPECT_OK(s2n_do_test_handshake(config, rsa_complete_chain,
                    S2N_TLS12, basic_handshake | CLIENT_AUTH | TLS12_PERFECT_FORWARD_SECRECY));

            /* Test: TLS1.3 + RSA + client auth */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, tls13_policy));
            EXPECT_OK(s2n_do_test_handshake(config, rsa_complete_chain,
                    s2n_get_highest_fully_supported_tls_version(), expected_handshake_with_tls13_policy | CLIENT_AUTH));
        };

        EXPECT_SUCCESS(s2n_config_free(config));
    };

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_complete_chain));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert_only_chain));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_complete_chain));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_cert_only_chain));

    END_TEST();
}
