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

#include "tls/extensions/s2n_extension_list.h"
#include "tls/extensions/s2n_client_server_name.h"
#include "crypto/s2n_hash.h"
#include "tls/s2n_tls.h"

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
    const char* expected_server_name = *(const char**) ctx;

    const char* actual_server_name = NULL;
    EXPECT_NOT_NULL(actual_server_name = s2n_get_server_name(conn));
    EXPECT_STRING_EQUAL(actual_server_name, expected_server_name);

    s2n_server_name_test_callback_flag = true;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13());

    /* Test s2n_connection does not grow too much.
     * s2n_connection is a very large structure. We should be working to reduce its
     * size, not increasing it.
     * This test documents changes to its size for reviewers so that we can
     * make very deliberate choices about increasing memory usage.
     *
     * We can't easily enforce an exact size for s2n_connection because it varies
     * based on some settings (like how many KEM groups are supported).
     */
    {
        /* Carefully consider any increases to this number. */
        const uint16_t max_connection_size = 14568;
        const uint16_t min_connection_size = max_connection_size * 0.75;

        size_t connection_size = sizeof(struct s2n_connection);

        if (connection_size > max_connection_size || connection_size < min_connection_size) {
            const char message[] = "s2n_connection size (%zu) no longer in (%i, %i). "
                    "Please verify that this change was intentional and then update this test.";
            char message_buffer[sizeof(message) + 100] = { 0 };
            int r = snprintf(message_buffer, sizeof(message_buffer), message,
                    connection_size, min_connection_size, max_connection_size);
            EXPECT_TRUE(r < sizeof(message_buffer));
            FAIL_MSG(message_buffer);
        }
    }

    /* s2n_get_server_name */
    {
        const char* test_server_name = "A server name";

        /* Safety check */
        EXPECT_NULL(s2n_get_server_name(NULL));

        /* Return NULL by default / for new connection */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_NULL(s2n_get_server_name(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Return server_name if set */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_set_server_name(conn, test_server_name));

            const char* actual_server_name = NULL;
            EXPECT_NOT_NULL(actual_server_name = s2n_get_server_name(conn));
            EXPECT_STRING_EQUAL(actual_server_name, test_server_name);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

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

            const char* actual_server_name = NULL;
            EXPECT_NOT_NULL(actual_server_name = s2n_get_server_name(server_conn));
            EXPECT_STRING_EQUAL(actual_server_name, test_server_name);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

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
        }
    }

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
    }

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

        s2n_tls_hash_algorithm expected_output[] = { S2N_TLS_HASH_NONE, S2N_TLS_HASH_MD5, 
                                                     S2N_TLS_HASH_SHA1, S2N_TLS_HASH_SHA224, 
                                                     S2N_TLS_HASH_SHA256, S2N_TLS_HASH_SHA384, 
                                                     S2N_TLS_HASH_SHA512, S2N_TLS_HASH_MD5_SHA1,
                                                     S2N_TLS_HASH_NONE };

        for (size_t i = S2N_TLS_HASH_NONE; i <= UINT16_MAX; i++) {
            conn->secure.client_cert_sig_scheme.hash_alg = i;
            conn->secure.conn_sig_scheme.hash_alg = i;
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
    }

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
            [ S2N_SIGNATURE_ANONYMOUS ] = S2N_TLS_SIGNATURE_ANONYMOUS,
            [ S2N_SIGNATURE_RSA ] = S2N_TLS_SIGNATURE_RSA,
            [ S2N_SIGNATURE_ECDSA ] = S2N_TLS_SIGNATURE_ECDSA,
            [ S2N_SIGNATURE_RSA_PSS_RSAE ] = S2N_TLS_SIGNATURE_RSA_PSS_RSAE,
            [ S2N_SIGNATURE_RSA_PSS_PSS ] = S2N_TLS_SIGNATURE_RSA_PSS_PSS,
        };

        for (size_t i = 0; i <= UINT16_MAX; i++) {
            conn->secure.client_cert_sig_scheme.sig_alg = i;
            conn->secure.conn_sig_scheme.sig_alg = i;

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
    }

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
        }

        /* Default behavior - set low mfl */
        {
            conn->max_outgoing_fragment_length = 1;
            EXPECT_OK(s2n_connection_set_max_fragment_length(conn, low_mfl));
            EXPECT_EQUAL(conn->max_outgoing_fragment_length, low_mfl);
            EXPECT_EQUAL(conn->out.blob.size, 0);
        }

        /* After extension - don't set mfl higher than agreed with peer */
        {
            conn->negotiated_mfl_code = mfl_code;
            conn->max_outgoing_fragment_length = 1;
            EXPECT_OK(s2n_connection_set_max_fragment_length(conn, high_mfl));
            EXPECT_EQUAL(conn->max_outgoing_fragment_length, mfl_code_value);
            EXPECT_EQUAL(conn->out.blob.size, 0);
        }

        /* After extension - set mfl lower than agreed with peer */
        {
            conn->negotiated_mfl_code = mfl_code;
            conn->max_outgoing_fragment_length = 1;
            EXPECT_OK(s2n_connection_set_max_fragment_length(conn, low_mfl));
            EXPECT_EQUAL(conn->max_outgoing_fragment_length, low_mfl);
            EXPECT_EQUAL(conn->out.blob.size, 0);
        }

        /* After extension - invalid negotiated mfl */
        {
            conn->negotiated_mfl_code = UINT8_MAX;
            EXPECT_ERROR_WITH_ERRNO(s2n_connection_set_max_fragment_length(conn, low_mfl), S2N_ERR_SAFETY);
            conn->negotiated_mfl_code = 0;
        }

        /* output IO buffer already allocated: resize for higher mfl */
        {
            EXPECT_SUCCESS(s2n_realloc(&conn->out.blob, 1));
            EXPECT_OK(s2n_connection_set_max_fragment_length(conn, S2N_TLS_MAXIMUM_FRAGMENT_LENGTH));
            EXPECT_EQUAL(conn->max_outgoing_fragment_length, S2N_TLS_MAXIMUM_FRAGMENT_LENGTH);
            EXPECT_EQUAL(conn->out.blob.size, S2N_TLS_MAXIMUM_RECORD_LENGTH);
            EXPECT_SUCCESS(s2n_free(&conn->out.blob));
        }

        /* output IO buffer already allocated: do nothing for lower mfl */
        {
            EXPECT_SUCCESS(s2n_realloc(&conn->out.blob, UINT16_MAX));
            EXPECT_OK(s2n_connection_set_max_fragment_length(conn, low_mfl));
            EXPECT_EQUAL(conn->max_outgoing_fragment_length, low_mfl);
            EXPECT_EQUAL(conn->out.blob.size, UINT16_MAX);
            EXPECT_SUCCESS(s2n_free(&conn->out.blob));
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
}
