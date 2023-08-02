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

#include "tls/s2n_connection.h"

#include "crypto/s2n_hash.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_client_server_name.h"
#include "tls/extensions/s2n_extension_list.h"
#include "tls/s2n_internal.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_socket.h"

const uint8_t actual_version = 1, client_version = 2, server_version = 3;
static int s2n_set_test_protocol_versions(struct s2n_connection *conn)
{
    conn->actual_protocol_version = actual_version;
    conn->client_protocol_version = client_version;
    conn->server_protocol_version = server_version;
    return S2N_SUCCESS;
}

bool s2n_server_name_test_callback_flag = false;
static int s2n_server_name_test_callback(struct s2n_connection *conn, void *ctx)
{
    const char *expected_server_name = *(const char **) ctx;

    const char *actual_server_name = NULL;
    EXPECT_NOT_NULL(actual_server_name = s2n_get_server_name(conn));
    EXPECT_STRING_EQUAL(actual_server_name, expected_server_name);

    s2n_server_name_test_callback_flag = true;
    return S2N_SUCCESS;
}

S2N_RESULT s2n_test_signature_scheme_valid(s2n_tls_signature_algorithm expected_sig_alg,
        s2n_tls_signature_algorithm server_sig_alg, s2n_tls_signature_algorithm client_sig_alg,
        s2n_tls_hash_algorithm server_hash_alg, s2n_tls_hash_algorithm client_hash_alg)
{
    /* The server and client should agree */
    RESULT_ENSURE_EQ(server_sig_alg, client_sig_alg);
    RESULT_ENSURE_EQ(server_hash_alg, client_hash_alg);

    /* The certificate dictates the signature algorithm, so we know the correct algorithm */
    RESULT_ENSURE_EQ(server_sig_alg, expected_sig_alg);

    /* The security policy dictates the hash algorithm,
     * but we used a default policy so we just expect a sane, non-legacy hash.
     */
    RESULT_ENSURE_NE(server_hash_alg, S2N_TLS_HASH_NONE);
    RESULT_ENSURE_NE(server_hash_alg, S2N_TLS_HASH_MD5);
    RESULT_ENSURE_NE(server_hash_alg, S2N_TLS_HASH_SHA1);
    RESULT_ENSURE_NE(server_hash_alg, S2N_TLS_HASH_MD5_SHA1);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_all_signature_schemes_valid(s2n_tls_signature_algorithm expected_sig_alg,
        struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    s2n_tls_signature_algorithm server_sig_alg = 0, client_sig_alg = 0;
    s2n_tls_hash_algorithm server_hash_alg = 0, client_hash_alg = 0;

    RESULT_GUARD_POSIX(s2n_connection_get_selected_signature_algorithm(client_conn, &client_sig_alg));
    RESULT_GUARD_POSIX(s2n_connection_get_selected_signature_algorithm(server_conn, &server_sig_alg));
    RESULT_GUARD_POSIX(s2n_connection_get_selected_digest_algorithm(client_conn, &client_hash_alg));
    RESULT_GUARD_POSIX(s2n_connection_get_selected_digest_algorithm(server_conn, &server_hash_alg));
    RESULT_GUARD(s2n_test_signature_scheme_valid(expected_sig_alg,
            server_sig_alg, client_sig_alg, server_hash_alg, client_hash_alg));

    RESULT_GUARD_POSIX(s2n_connection_get_selected_client_cert_signature_algorithm(client_conn, &client_sig_alg));
    RESULT_GUARD_POSIX(s2n_connection_get_selected_client_cert_signature_algorithm(server_conn, &server_sig_alg));
    RESULT_GUARD_POSIX(s2n_connection_get_selected_client_cert_digest_algorithm(client_conn, &client_hash_alg));
    RESULT_GUARD_POSIX(s2n_connection_get_selected_client_cert_digest_algorithm(server_conn, &server_hash_alg));
    RESULT_GUARD(s2n_test_signature_scheme_valid(expected_sig_alg,
            server_sig_alg, client_sig_alg, server_hash_alg, client_hash_alg));

    return S2N_RESULT_OK;
}

int s2n_noop_recv_cb(void *io_context, uint8_t *buf, uint32_t len)
{
    return 0;
}

int s2n_noop_send_cb(void *io_context, const uint8_t *buf, uint32_t len)
{
    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    struct s2n_cert_chain_and_key *rsa_chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* s2n_get_server_name */
    {
        const char *test_server_name = "A server name";

        /* Safety check */
        EXPECT_NULL(s2n_get_server_name(NULL));

        /* Return NULL by default / for new connection */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_NULL(s2n_get_server_name(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Return server_name if set */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_set_server_name(conn, test_server_name));

            const char *actual_server_name = NULL;
            EXPECT_NOT_NULL(actual_server_name = s2n_get_server_name(conn));
            EXPECT_STRING_EQUAL(actual_server_name, test_server_name);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Return server_name if server_name extension parsed, but not yet processed */
        {
            struct s2n_connection *client_conn, *server_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, test_server_name));
            EXPECT_SUCCESS(s2n_client_server_name_extension.send(client_conn, &stuffer));

            s2n_extension_type_id extension_id;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_SERVER_NAME, &extension_id));
            server_conn->client_hello.extensions.parsed_extensions[extension_id].extension_type = TLS_EXTENSION_SERVER_NAME;
            server_conn->client_hello.extensions.parsed_extensions[extension_id].extension = stuffer.blob;

            const char *actual_server_name = NULL;
            EXPECT_NOT_NULL(actual_server_name = s2n_get_server_name(server_conn));
            EXPECT_STRING_EQUAL(actual_server_name, test_server_name);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Test retrieving server_name via ClientHello callback,
         * which is when we expect this API to be called. */
        {
            s2n_server_name_test_callback_flag = false;

            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, s2n_server_name_test_callback, &test_server_name));

            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, test_server_name));

            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));

            /* This function can succeed or fail -- it doesn't affect the test. */
            s2n_client_hello_recv(server_conn);

            /* Make sure the callback actually fired. If it did,
             * then the actual test ran and we have verified the server name. */
            EXPECT_TRUE(s2n_server_name_test_callback_flag);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };
    };

    /* s2n_connection_get_protocol_version */
    {
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_set_test_protocol_versions(client_conn));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_set_test_protocol_versions(server_conn));

        /* Handle null */
        EXPECT_EQUAL(s2n_connection_get_protocol_version(NULL), S2N_UNKNOWN_PROTOCOL_VERSION);

        /* Return actual if set */
        EXPECT_EQUAL(s2n_connection_get_protocol_version(client_conn), actual_version);
        EXPECT_EQUAL(s2n_connection_get_protocol_version(server_conn), actual_version);

        /* If actual version not set, result version for mode */
        client_conn->actual_protocol_version = S2N_UNKNOWN_PROTOCOL_VERSION;
        EXPECT_EQUAL(s2n_connection_get_protocol_version(client_conn), client_version);
        server_conn->actual_protocol_version = S2N_UNKNOWN_PROTOCOL_VERSION;
        EXPECT_EQUAL(s2n_connection_get_protocol_version(server_conn), server_version);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Test: get selected digest alg */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        s2n_tls_hash_algorithm output = { 0 };

        EXPECT_FAILURE(s2n_connection_get_selected_digest_algorithm(NULL, &output));
        EXPECT_FAILURE(s2n_connection_get_selected_digest_algorithm(conn, NULL));
        EXPECT_FAILURE(s2n_connection_get_selected_client_cert_digest_algorithm(NULL, &output));
        EXPECT_FAILURE(s2n_connection_get_selected_client_cert_digest_algorithm(conn, NULL));

        EXPECT_SUCCESS(s2n_connection_get_selected_client_cert_digest_algorithm(conn, &output));
        EXPECT_EQUAL(S2N_TLS_HASH_NONE, output);

        EXPECT_SUCCESS(s2n_connection_get_selected_digest_algorithm(conn, &output));
        EXPECT_EQUAL(S2N_TLS_HASH_NONE, output);

        s2n_tls_hash_algorithm expected_output[] = {
            S2N_TLS_HASH_NONE, S2N_TLS_HASH_MD5,
            S2N_TLS_HASH_SHA1, S2N_TLS_HASH_SHA224,
            S2N_TLS_HASH_SHA256, S2N_TLS_HASH_SHA384,
            S2N_TLS_HASH_SHA512, S2N_TLS_HASH_MD5_SHA1,
            S2N_TLS_HASH_NONE
        };

        for (size_t i = S2N_TLS_HASH_NONE; i <= UINT16_MAX; i++) {
            struct s2n_signature_scheme test_scheme = *conn->handshake_params.client_cert_sig_scheme;
            test_scheme.hash_alg = i;
            conn->handshake_params.client_cert_sig_scheme = &test_scheme;
            conn->handshake_params.server_cert_sig_scheme = &test_scheme;
            if (i <= S2N_HASH_SENTINEL) {
                EXPECT_SUCCESS(s2n_connection_get_selected_client_cert_digest_algorithm(conn, &output));
                EXPECT_EQUAL(expected_output[i], output);

                EXPECT_SUCCESS(s2n_connection_get_selected_digest_algorithm(conn, &output));
                EXPECT_EQUAL(expected_output[i], output);
            } else {
                EXPECT_SUCCESS(s2n_connection_get_selected_client_cert_digest_algorithm(conn, &output));
                EXPECT_EQUAL(S2N_TLS_HASH_NONE, output);

                EXPECT_SUCCESS(s2n_connection_get_selected_digest_algorithm(conn, &output));
                EXPECT_EQUAL(S2N_TLS_HASH_NONE, output);
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: get selected signature alg */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        s2n_tls_signature_algorithm output = { 0 };

        EXPECT_FAILURE(s2n_connection_get_selected_signature_algorithm(NULL, &output));
        EXPECT_FAILURE(s2n_connection_get_selected_signature_algorithm(conn, NULL));
        EXPECT_FAILURE(s2n_connection_get_selected_client_cert_signature_algorithm(NULL, &output));
        EXPECT_FAILURE(s2n_connection_get_selected_client_cert_signature_algorithm(conn, NULL));

        EXPECT_SUCCESS(s2n_connection_get_selected_client_cert_signature_algorithm(conn, &output));
        EXPECT_EQUAL(S2N_TLS_SIGNATURE_ANONYMOUS, output);

        EXPECT_SUCCESS(s2n_connection_get_selected_signature_algorithm(conn, &output));
        EXPECT_EQUAL(S2N_TLS_SIGNATURE_ANONYMOUS, output);

        s2n_tls_signature_algorithm expected_output[] = {
            [S2N_SIGNATURE_ANONYMOUS] = S2N_TLS_SIGNATURE_ANONYMOUS,
            [S2N_SIGNATURE_RSA] = S2N_TLS_SIGNATURE_RSA,
            [S2N_SIGNATURE_ECDSA] = S2N_TLS_SIGNATURE_ECDSA,
            [S2N_SIGNATURE_RSA_PSS_RSAE] = S2N_TLS_SIGNATURE_RSA_PSS_RSAE,
            [S2N_SIGNATURE_RSA_PSS_PSS] = S2N_TLS_SIGNATURE_RSA_PSS_PSS,
        };

        for (size_t i = 0; i <= UINT16_MAX; i++) {
            struct s2n_signature_scheme test_scheme = *conn->handshake_params.client_cert_sig_scheme;
            test_scheme.sig_alg = i;
            conn->handshake_params.client_cert_sig_scheme = &test_scheme;
            conn->handshake_params.server_cert_sig_scheme = &test_scheme;

            if (i < s2n_array_len(expected_output)) {
                EXPECT_SUCCESS(s2n_connection_get_selected_client_cert_signature_algorithm(conn, &output));
                EXPECT_EQUAL(expected_output[i], output);

                EXPECT_SUCCESS(s2n_connection_get_selected_signature_algorithm(conn, &output));
                EXPECT_EQUAL(expected_output[i], output);
            } else {
                EXPECT_SUCCESS(s2n_connection_get_selected_client_cert_signature_algorithm(conn, &output));
                EXPECT_EQUAL(S2N_TLS_SIGNATURE_ANONYMOUS, output);

                EXPECT_SUCCESS(s2n_connection_get_selected_signature_algorithm(conn, &output));
                EXPECT_EQUAL(S2N_TLS_SIGNATURE_ANONYMOUS, output);
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: signature algorithm and hash can be retrieved after the handshake.
     * Check both TLS1.2 and TLS1.3, because they use different signature negotiation logic.
     * Check for both the server and client certificates, because they use different negotiation logic.
     */
    {
        /* TLS1.3 */
        if (s2n_is_tls13_fully_supported()) {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_OK(s2n_test_all_signature_schemes_valid(S2N_TLS_SIGNATURE_ECDSA, server_conn, client_conn));

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* TLS1.2 */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, rsa_chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
            EXPECT_OK(s2n_test_all_signature_schemes_valid(S2N_TLS_SIGNATURE_RSA, server_conn, client_conn));

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
            EXPECT_SUCCESS(s2n_config_free(config));
        };
    };

    /* s2n_connection_set_max_fragment_length */
    {
        const uint8_t mfl_code = S2N_TLS_MAX_FRAG_LEN_1024;
        const uint16_t mfl_code_value = 1024;
        const uint16_t low_mfl = 10;
        const uint16_t high_mfl = UINT16_MAX;

        /* Safety check */
        EXPECT_ERROR_WITH_ERRNO(s2n_connection_set_max_fragment_length(NULL, 1), S2N_ERR_NULL);

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        /* Default behavior - set high mfl */
        {
            conn->max_outgoing_fragment_length = 1;
            EXPECT_OK(s2n_connection_set_max_fragment_length(conn, high_mfl));
            EXPECT_EQUAL(conn->max_outgoing_fragment_length, high_mfl);
            EXPECT_EQUAL(conn->out.blob.size, 0);
        };

        /* Default behavior - set low mfl */
        {
            conn->max_outgoing_fragment_length = 1;
            EXPECT_OK(s2n_connection_set_max_fragment_length(conn, low_mfl));
            EXPECT_EQUAL(conn->max_outgoing_fragment_length, low_mfl);
            EXPECT_EQUAL(conn->out.blob.size, 0);
        };

        /* After extension - don't set mfl higher than agreed with peer */
        {
            conn->negotiated_mfl_code = mfl_code;
            conn->max_outgoing_fragment_length = 1;
            EXPECT_OK(s2n_connection_set_max_fragment_length(conn, high_mfl));
            EXPECT_EQUAL(conn->max_outgoing_fragment_length, mfl_code_value);
            EXPECT_EQUAL(conn->out.blob.size, 0);
        };

        /* After extension - set mfl lower than agreed with peer */
        {
            conn->negotiated_mfl_code = mfl_code;
            conn->max_outgoing_fragment_length = 1;
            EXPECT_OK(s2n_connection_set_max_fragment_length(conn, low_mfl));
            EXPECT_EQUAL(conn->max_outgoing_fragment_length, low_mfl);
            EXPECT_EQUAL(conn->out.blob.size, 0);
        };

        /* After extension - invalid negotiated mfl */
        {
            conn->negotiated_mfl_code = UINT8_MAX;
            EXPECT_ERROR_WITH_ERRNO(s2n_connection_set_max_fragment_length(conn, low_mfl), S2N_ERR_SAFETY);
            conn->negotiated_mfl_code = 0;
        };

        /* output IO buffer already allocated: resize for higher mfl */
        {
            EXPECT_SUCCESS(s2n_realloc(&conn->out.blob, 1));
            EXPECT_OK(s2n_connection_set_max_fragment_length(conn, S2N_TLS_MAXIMUM_FRAGMENT_LENGTH));
            EXPECT_EQUAL(conn->max_outgoing_fragment_length, S2N_TLS_MAXIMUM_FRAGMENT_LENGTH);
            EXPECT_EQUAL(conn->out.blob.size, S2N_TLS_MAXIMUM_RECORD_LENGTH);
            EXPECT_SUCCESS(s2n_free(&conn->out.blob));
        };

        /* output IO buffer already allocated: do nothing for lower mfl */
        {
            EXPECT_SUCCESS(s2n_realloc(&conn->out.blob, UINT16_MAX));
            EXPECT_OK(s2n_connection_set_max_fragment_length(conn, low_mfl));
            EXPECT_EQUAL(conn->max_outgoing_fragment_length, low_mfl);
            EXPECT_EQUAL(conn->out.blob.size, UINT16_MAX);
            EXPECT_SUCCESS(s2n_free(&conn->out.blob));
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* s2n_connection set fd functionality */
    {
        static const int READFD = 1;
        static const int WRITEFD = 2;
        static int getReadFd, getWriteFd;

        /* Safety checks */
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_fd(NULL, READFD), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_read_fd(NULL, READFD), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_write_fd(NULL, WRITEFD), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_write_fd(NULL, &getWriteFd), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_read_fd(NULL, &getReadFd), S2N_ERR_NULL);

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        /* check getter API after s2n_connection_set_fd */
        EXPECT_SUCCESS(s2n_connection_set_fd(conn, READFD));
        EXPECT_SUCCESS(s2n_connection_get_write_fd(conn, &getWriteFd));
        EXPECT_SUCCESS(s2n_connection_get_read_fd(conn, &getReadFd));
        EXPECT_EQUAL(getReadFd, READFD);
        EXPECT_EQUAL(getWriteFd, READFD);

        /* check getter API after s2n_connection_set_read_fd */
        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, READFD));
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_write_fd(conn, &getWriteFd), S2N_ERR_INVALID_STATE);
        EXPECT_SUCCESS(s2n_connection_get_read_fd(conn, &getReadFd));
        EXPECT_EQUAL(getReadFd, READFD);

        /* check getter API after s2n_connection_set_write_fd */
        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, WRITEFD));
        EXPECT_SUCCESS(s2n_connection_get_write_fd(conn, &getWriteFd));
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_read_fd(conn, &getReadFd), S2N_ERR_INVALID_STATE);
        EXPECT_EQUAL(getWriteFd, WRITEFD);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* s2n_connection_set_fd can be called twice in a row */
    {
        static const int OLDFD = 1;
        static const int NEWFD = 2;
        static int getReadFd, getWriteFd;

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        EXPECT_SUCCESS(s2n_connection_set_fd(conn, OLDFD));
        EXPECT_SUCCESS(s2n_connection_set_fd(conn, NEWFD));

        EXPECT_SUCCESS(s2n_connection_get_write_fd(conn, &getWriteFd));
        EXPECT_SUCCESS(s2n_connection_get_read_fd(conn, &getReadFd));
        EXPECT_EQUAL(getReadFd, NEWFD);
        EXPECT_EQUAL(getWriteFd, NEWFD);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* s2n_connection_set_read_fd and s2n_connection_set_write_fd can be called
     * after s2n_connection_set_fd */
    {
        static const int OLDFD = 1;
        static const int NEWFD = 2;
        static int getReadFd, getWriteFd;

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        EXPECT_SUCCESS(s2n_connection_set_fd(conn, OLDFD));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, NEWFD));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, NEWFD));

        EXPECT_SUCCESS(s2n_connection_get_write_fd(conn, &getWriteFd));
        EXPECT_SUCCESS(s2n_connection_get_read_fd(conn, &getReadFd));
        EXPECT_EQUAL(getReadFd, NEWFD);
        EXPECT_EQUAL(getWriteFd, NEWFD);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* The default s2n socket read/write setup can be used with a user-defined send/recv setup */
    {
        static const int READFD = 1;
        static const int WRITEFD = 2;
        uint8_t socket_ctx[] = { "Some test context" };

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, READFD));
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_noop_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, socket_ctx));

        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, WRITEFD));
        EXPECT_SUCCESS(s2n_connection_set_recv_cb(conn, s2n_noop_recv_cb));
        EXPECT_SUCCESS(s2n_connection_set_recv_ctx(conn, socket_ctx));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* The default s2n socket read/write setup can be overwritten by custom socket setup */
    {
        static const int READFD = 1;
        uint8_t socket_ctx[] = { "Some test context" };

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        /* Connection sets up the default socket functions */
        EXPECT_SUCCESS(s2n_connection_set_fd(conn, READFD));
        EXPECT_NOT_NULL(conn->send);
        EXPECT_NOT_NULL(conn->recv);

        /* Setting up custom socket contexts will remove default socket functions */
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, socket_ctx));
        EXPECT_SUCCESS(s2n_connection_set_recv_ctx(conn, socket_ctx));
        EXPECT_NULL(conn->send);
        EXPECT_NULL(conn->recv);

        /* Setup default socket functions again */
        EXPECT_SUCCESS(s2n_connection_set_fd(conn, READFD));
        EXPECT_NOT_NULL(conn->send_io_context);
        EXPECT_NOT_NULL(conn->recv_io_context);

        /* Setting up custom socket functions will remove default socket contexts */
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_noop_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_recv_cb(conn, s2n_noop_recv_cb));
        EXPECT_NULL(conn->send_io_context);
        EXPECT_NULL(conn->recv_io_context);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_connection_get_config */
    {
        struct s2n_config *returned_config = NULL;
        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_config(conn, &returned_config), S2N_ERR_NULL);

        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_SUCCESS(s2n_connection_get_config(conn, &returned_config));
        EXPECT_EQUAL(returned_config, config);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test s2n_connection_get_wire_bytes_out */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_EQUAL(0, s2n_connection_get_wire_bytes_out(conn));

        uint64_t magic_number = 123456;
        conn->wire_bytes_out = magic_number;
        EXPECT_EQUAL(magic_number, s2n_connection_get_wire_bytes_out(conn));
    };

    /* Test connection reuse when memory freed */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_chain_and_key));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        uint8_t app_data[100] = "hello world";
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        for (size_t i = 0; i < 10; i++) {
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Handshake */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Free handshake memory */
            EXPECT_SUCCESS(s2n_connection_free_handshake(client_conn));
            EXPECT_SUCCESS(s2n_connection_free_handshake(server_conn));

            /* Send and recv data */
            EXPECT_EQUAL(s2n_send(client_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
            EXPECT_EQUAL(s2n_recv(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
            EXPECT_EQUAL(s2n_send(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
            EXPECT_EQUAL(s2n_recv(client_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));

            /* Free io buffers */
            EXPECT_SUCCESS(s2n_connection_release_buffers(client_conn));
            EXPECT_SUCCESS(s2n_connection_release_buffers(server_conn));

            /* Reuse connections */
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        }
    };

    /* Test post-handshake buffer lifecycle */
    {
        const uint32_t size = 10;

        /* Test s2n_connection_wipe */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            /* Test uninitialized */
            for (size_t i = 0; i < 3; i++) {
                EXPECT_FALSE(conn->post_handshake.in.growable);
                EXPECT_FALSE(conn->post_handshake.in.alloced);
                EXPECT_EQUAL(conn->post_handshake.in.blob.size, 0);

                EXPECT_SUCCESS(s2n_connection_wipe(conn));
                EXPECT_EQUAL(conn->post_handshake.in.blob.size, 0);
            }

            /* Test with dynamic buffer */
            for (size_t i = 0; i < 3; i++) {
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&conn->post_handshake.in, size));
                EXPECT_TRUE(conn->post_handshake.in.growable);
                EXPECT_TRUE(conn->post_handshake.in.alloced);
                EXPECT_EQUAL(conn->post_handshake.in.blob.size, size);

                EXPECT_SUCCESS(s2n_connection_wipe(conn));
                EXPECT_EQUAL(conn->post_handshake.in.blob.size, 0);
            }

            /* Test with static buffer */
            for (size_t i = 0; i < 3; i++) {
                struct s2n_blob static_blob = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&static_blob, conn->post_handshake.header_in,
                        sizeof(conn->post_handshake.header_in)));
                EXPECT_SUCCESS(s2n_stuffer_init(&conn->post_handshake.in, &static_blob));
                EXPECT_FALSE(conn->post_handshake.in.growable);
                EXPECT_FALSE(conn->post_handshake.in.alloced);
                EXPECT_NOT_EQUAL(conn->post_handshake.in.blob.size, 0);

                EXPECT_SUCCESS(s2n_connection_wipe(conn));
                EXPECT_EQUAL(conn->post_handshake.in.blob.size, 0);
            }
        };

        /* Test s2n_connection_release_buffers */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            /* Test uninitialized */
            for (size_t i = 0; i < 3; i++) {
                EXPECT_FALSE(conn->post_handshake.in.growable);
                EXPECT_FALSE(conn->post_handshake.in.alloced);
                EXPECT_EQUAL(conn->post_handshake.in.blob.size, 0);

                EXPECT_SUCCESS(s2n_connection_release_buffers(conn));
                EXPECT_EQUAL(conn->post_handshake.in.blob.size, 0);
            }

            /* Test with dynamic buffer */
            for (size_t i = 0; i < 3; i++) {
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&conn->post_handshake.in, size));
                EXPECT_TRUE(conn->post_handshake.in.growable);
                EXPECT_TRUE(conn->post_handshake.in.alloced);
                EXPECT_EQUAL(conn->post_handshake.in.blob.size, size);

                EXPECT_SUCCESS(s2n_connection_release_buffers(conn));
                EXPECT_EQUAL(conn->post_handshake.in.blob.size, 0);
            }

            /* Test with static memory */
            for (size_t i = 0; i < 3; i++) {
                struct s2n_blob static_blob = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&static_blob, conn->post_handshake.header_in,
                        sizeof(conn->post_handshake.header_in)));
                EXPECT_SUCCESS(s2n_stuffer_init(&conn->post_handshake.in, &static_blob));
                EXPECT_FALSE(conn->post_handshake.in.growable);
                EXPECT_FALSE(conn->post_handshake.in.alloced);
                EXPECT_NOT_EQUAL(conn->post_handshake.in.blob.size, 0);

                EXPECT_SUCCESS(s2n_connection_release_buffers(conn));
                EXPECT_EQUAL(conn->post_handshake.in.blob.size, 0);
            }

            /* Fails to release if in use */
            {
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&conn->post_handshake.in, size));
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->post_handshake.in, 1));
                EXPECT_FAILURE_WITH_ERRNO(s2n_connection_release_buffers(conn),
                        S2N_ERR_STUFFER_HAS_UNPROCESSED_DATA);
                EXPECT_NOT_EQUAL(conn->post_handshake.in.blob.size, 0);
            };
        };
    };

    /* Test: s2n_connection_check_io_status */
    {
        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            EXPECT_FALSE(s2n_connection_check_io_status(NULL, S2N_IO_WRITABLE));
            EXPECT_FALSE(s2n_connection_check_io_status(NULL, S2N_IO_READABLE));
            EXPECT_FALSE(s2n_connection_check_io_status(NULL, S2N_IO_FULL_DUPLEX));
            EXPECT_FALSE(s2n_connection_check_io_status(NULL, S2N_IO_CLOSED));
            EXPECT_FALSE(s2n_connection_check_io_status(NULL, 10));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, 10));
        }

        /* TLS1.2 */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS12;

            /* Full duplex by default */
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));

            /* Close write */
            s2n_atomic_flag_set(&conn->write_closed);
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
            s2n_atomic_flag_clear(&conn->write_closed);

            /* Close read */
            s2n_atomic_flag_set(&conn->read_closed);
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
            s2n_atomic_flag_clear(&conn->read_closed);

            /* Close both */
            s2n_atomic_flag_set(&conn->read_closed);
            s2n_atomic_flag_set(&conn->write_closed);
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
        };

        /* TLS1.3 */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS13;

            /* Full duplex by default */
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));

            /* Close write */
            s2n_atomic_flag_set(&conn->write_closed);
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
            s2n_atomic_flag_clear(&conn->write_closed);

            /* Close read */
            s2n_atomic_flag_set(&conn->read_closed);
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
            s2n_atomic_flag_clear(&conn->read_closed);

            /* Close both */
            s2n_atomic_flag_set(&conn->read_closed);
            s2n_atomic_flag_set(&conn->write_closed);
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
        };
    };

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_chain_and_key));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_chain_and_key));
    END_TEST();
}
