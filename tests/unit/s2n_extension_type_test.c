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

#include "tls/extensions/s2n_extension_type.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_extension_type_lists.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_bitmap.h"

#define S2N_TEST_DATA_LEN 20

#define EXPECT_BITFIELD_CLEAR(field) EXPECT_BYTEARRAY_EQUAL((field), &empty_bitfield, S2N_SUPPORTED_EXTENSIONS_BITFIELD_LEN)

s2n_extension_type_id s2n_extension_iana_value_to_id(uint16_t iana_value);

const s2n_extension_bitfield empty_bitfield = { 0 };

static int test_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    return s2n_stuffer_skip_write(out, S2N_TEST_DATA_LEN);
}

static int test_send_too_much_data(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    return s2n_stuffer_skip_write(out, UINT16_MAX + 1);
}

static int test_recv(struct s2n_connection *conn, struct s2n_stuffer *in)
{
    return S2N_SUCCESS;
}

const s2n_extension_type test_extension_type = {
    .iana_value = TLS_EXTENSION_SUPPORTED_VERSIONS,
    .is_response = false,
    .send = test_send,
    .recv = test_recv,
    .should_send = s2n_extension_always_send,
    .if_missing = s2n_extension_noop_if_missing,
};

int main()
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Test common implementations of methods */
    {
        /* Test common implementations for send */
        EXPECT_FAILURE_WITH_ERRNO(s2n_extension_send_unimplemented(NULL, NULL), S2N_ERR_UNIMPLEMENTED);
        EXPECT_SUCCESS(s2n_extension_send_noop(NULL, NULL));

        /* Test common implementations for recv */
        EXPECT_FAILURE_WITH_ERRNO(s2n_extension_recv_unimplemented(NULL, NULL), S2N_ERR_UNIMPLEMENTED);
        EXPECT_SUCCESS(s2n_extension_recv_noop(NULL, NULL));

        /* Test common implementations for should_send */
        {
            EXPECT_TRUE(s2n_extension_always_send(NULL));
            EXPECT_FALSE(s2n_extension_never_send(NULL));

            struct s2n_connection conn = { 0 };
            conn.actual_protocol_version = S2N_TLS12;
            EXPECT_FALSE(s2n_extension_send_if_tls13_connection(&conn));
            conn.actual_protocol_version = S2N_TLS13;
            EXPECT_TRUE(s2n_extension_send_if_tls13_connection(&conn));
        };

        /* Test common implementations for if_missing */
        EXPECT_FAILURE_WITH_ERRNO(s2n_extension_error_if_missing(NULL), S2N_ERR_MISSING_EXTENSION);
        EXPECT_SUCCESS(s2n_extension_noop_if_missing(NULL));
    };

    /* Test s2n_extension_iana_value_to_id */
    {
        /* Extension appearing in the lookup table can be handled */
        EXPECT_EQUAL(s2n_extension_iana_value_to_id(s2n_supported_extensions[5]), 5);

        /* Unknown extension in the lookup table can be handled
         * 15 == heartbeat, which s2n will probably never support :) */
        EXPECT_EQUAL(s2n_extension_iana_value_to_id(15), s2n_unsupported_extension);

        /* Extension with iana too large for the lookup table can be handled */
        EXPECT_EQUAL(s2n_extension_iana_value_to_id(TLS_EXTENSION_RENEGOTIATION_INFO), 0);

        /* Unknown extension with iana too large for the lookup table can be handled
         * 65280 == grease value (see https://tools.ietf.org/html/rfc8701) */
        EXPECT_EQUAL(s2n_extension_iana_value_to_id(65280), s2n_unsupported_extension);

        /* Every supported extension can be handled */
        for (size_t i = 0; i < S2N_SUPPORTED_EXTENSIONS_COUNT; i++) {
            EXPECT_EQUAL(s2n_extension_iana_value_to_id(s2n_supported_extensions[i]), i);
        }
    };

    /* Test s2n_extension_supported_iana_value_to_id */
    {
        s2n_extension_type_id id = s2n_unsupported_extension;

        /* Supported extension id returned */
        const uint16_t supported_extension_id = 5;
        EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(s2n_supported_extensions[supported_extension_id], &id));
        EXPECT_EQUAL(id, supported_extension_id);

        /* Fail on unsupported iana value
         * 15 == heartbeat, which s2n will probably never support :) */
        EXPECT_FAILURE_WITH_ERRNO(s2n_extension_supported_iana_value_to_id(15, &id),
                S2N_ERR_UNRECOGNIZED_EXTENSION);
    };

    /* Test bitfield behavior */
    {
        s2n_extension_bitfield test_bitfield = { 0 };
        for (size_t i = 0; i < S2N_SUPPORTED_EXTENSIONS_COUNT; i++) {
            uint16_t iana = s2n_supported_extensions[i];
            s2n_extension_type_id id = s2n_extension_iana_value_to_id(iana);

            EXPECT_FALSE(S2N_CBIT_TEST(test_bitfield, id));
            S2N_CBIT_SET(test_bitfield, id);
            EXPECT_TRUE(S2N_CBIT_TEST(test_bitfield, id));
            S2N_CBIT_CLR(test_bitfield, id);
            EXPECT_FALSE(S2N_CBIT_TEST(test_bitfield, id));
        }
    };

    s2n_extension_type_id test_extension_id = s2n_extension_iana_value_to_id(test_extension_type.iana_value);
    EXPECT_NOT_EQUAL(test_extension_id, s2n_unsupported_extension);

    /* Test s2n_extension_recv */
    {
        struct s2n_stuffer stuffer = { 0 };

        /* null check tests */
        {
            struct s2n_connection conn = { 0 };

            EXPECT_FAILURE(s2n_extension_recv(NULL, &conn, &stuffer));
            EXPECT_FAILURE(s2n_extension_recv(&test_extension_type, NULL, &stuffer));

            s2n_extension_type extension_type_with_null_recv = test_extension_type;
            extension_type_with_null_recv.recv = NULL;
            EXPECT_FAILURE(s2n_extension_recv(&extension_type_with_null_recv, &conn, &stuffer));
        };

        /* request extension */
        {
            struct s2n_connection conn = { 0 };
            s2n_extension_type request_extension_type = test_extension_type;
            request_extension_type.is_response = false;

            /* Succeeds and sets request flag */
            EXPECT_SUCCESS(s2n_extension_recv(&request_extension_type, &conn, &stuffer));
            EXPECT_TRUE(S2N_CBIT_TEST(conn.extension_requests_received, test_extension_id));
        };

        /**
         * Ensure response extensions are only received if sent
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2
         *= type=test
         *# Upon receiving such an extension, an endpoint MUST abort the handshake
         *# with an "unsupported_extension" alert.
         *
         *= https://tools.ietf.org/rfc/rfc7627#section-5.3
         *= type=test
         *# If the original session did not use the "extended_master_secret"
         *# extension but the new ServerHello contains the extension, the
         *# client MUST abort the handshake.
         *
         *= https://tools.ietf.org/rfc/rfc8446#4.1.4
         *= type=test
         *# As with the ServerHello, a HelloRetryRequest MUST NOT contain any
         *# extensions that were not first offered by the client in its
         *# ClientHello, with the exception of optionally the "cookie" (see
         *# Section 4.2.2) extension.
         **/
        {
            struct s2n_connection conn = { 0 };
            s2n_extension_type response_extension_type = test_extension_type;
            response_extension_type.is_response = true;

            /* Fails if request was not sent */
            EXPECT_FAILURE_WITH_ERRNO(s2n_extension_recv(&response_extension_type, &conn, &stuffer), S2N_ERR_UNSUPPORTED_EXTENSION);
            /* cppcheck-suppress sizeofDivisionMemfunc */
            EXPECT_BITFIELD_CLEAR(conn.extension_requests_received);

            /* Succeeds (but does not set request flag) if request was sent */
            S2N_CBIT_SET(conn.extension_requests_sent, test_extension_id);
            EXPECT_SUCCESS(s2n_extension_recv(&response_extension_type, &conn, &stuffer));
            /* cppcheck-suppress sizeofDivisionMemfunc */
            EXPECT_BITFIELD_CLEAR(conn.extension_requests_received);
        };

        /* "recv" errors */
        {
            struct s2n_connection conn = { 0 };
            s2n_extension_type extension_type_with_failure = test_extension_type;
            extension_type_with_failure.recv = s2n_extension_recv_unimplemented;

            EXPECT_FAILURE_WITH_ERRNO(s2n_extension_recv(&extension_type_with_failure, &conn, &stuffer), S2N_ERR_UNIMPLEMENTED);
            /* cppcheck-suppress sizeofDivisionMemfunc */
            EXPECT_BITFIELD_CLEAR(conn.extension_requests_received);
        };
    };

    /* Test s2n_extension_send */
    {
        /* null check tests */
        {
            struct s2n_connection conn = { 0 };
            struct s2n_stuffer stuffer = { 0 };

            EXPECT_FAILURE(s2n_extension_send(NULL, &conn, &stuffer));
            EXPECT_FAILURE(s2n_extension_send(&test_extension_type, NULL, &stuffer));

            s2n_extension_type extension_type_with_null_send = test_extension_type;
            extension_type_with_null_send.send = NULL;
            EXPECT_FAILURE(s2n_extension_send(&extension_type_with_null_send, &conn, &stuffer));

            s2n_extension_type extension_type_with_null_should_send = test_extension_type;
            extension_type_with_null_should_send.should_send = NULL;
            EXPECT_FAILURE(s2n_extension_send(&extension_type_with_null_should_send, &conn, &stuffer));
        };

        /* request extension */
        {
            struct s2n_connection conn = { 0 };
            struct s2n_stuffer stuffer = { 0 };
            s2n_stuffer_alloc(&stuffer, S2N_TEST_DATA_LEN * 2);

            s2n_extension_type request_extension_type = test_extension_type;
            request_extension_type.is_response = false;

            /* Succeeds and sets request flag */
            EXPECT_SUCCESS(s2n_extension_send(&request_extension_type, &conn, &stuffer));
            EXPECT_TRUE(S2N_CBIT_TEST(conn.extension_requests_sent, test_extension_id));

            /* writes iana_value */
            uint16_t iana_value;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &iana_value));
            EXPECT_EQUAL(iana_value, request_extension_type.iana_value);

            /* writes length */
            uint16_t length;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &length));
            EXPECT_EQUAL(length, s2n_stuffer_data_available(&stuffer));
            EXPECT_EQUAL(length, S2N_TEST_DATA_LEN);

            s2n_stuffer_free(&stuffer);
        };

        /**
         * Ensure correct response extension send behavior
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2
         *= type=test
         *# Implementations MUST NOT send extension responses if the remote
         *# endpoint did not send the corresponding extension requests, with the
         *# exception of the "cookie" extension in the HelloRetryRequest.
         *
         *= https://tools.ietf.org/rfc/rfc8446#4.1.4
         *= type=test
         *# As with the ServerHello, a HelloRetryRequest MUST NOT contain any
         *# extensions that were not first offered by the client in its
         *# ClientHello, with the exception of optionally the "cookie" (see
         *# Section 4.2.2) extension.
         **/
        {
            struct s2n_connection conn = { 0 };
            struct s2n_stuffer stuffer = { 0 };
            s2n_stuffer_alloc(&stuffer, S2N_TEST_DATA_LEN * 2);

            s2n_extension_type response_extension_type = test_extension_type;
            response_extension_type.is_response = true;

            /* Succeeds but no-op if request was not received */
            EXPECT_SUCCESS(s2n_extension_send(&response_extension_type, &conn, &stuffer));
            EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));
            /* cppcheck-suppress sizeofDivisionMemfunc */
            EXPECT_BITFIELD_CLEAR(conn.extension_requests_sent);

            /* Succeeds (but does not set request flag) if request was received */
            S2N_CBIT_SET(conn.extension_requests_received, test_extension_id);
            EXPECT_SUCCESS(s2n_extension_send(&response_extension_type, &conn, &stuffer));
            /* cppcheck-suppress sizeofDivisionMemfunc */
            EXPECT_BITFIELD_CLEAR(conn.extension_requests_sent);

            /* writes iana_value */
            uint16_t iana_value;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &iana_value));
            EXPECT_EQUAL(iana_value, response_extension_type.iana_value);

            /* writes length */
            uint16_t length;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &length));
            EXPECT_EQUAL(length, s2n_stuffer_data_available(&stuffer));
            EXPECT_EQUAL(length, S2N_TEST_DATA_LEN);

            s2n_stuffer_free(&stuffer);
        };

        /* "should_send" returns false */
        {
            struct s2n_connection conn = { 0 };
            struct s2n_stuffer stuffer = { 0 };

            s2n_extension_type extension_type_with_never_send = test_extension_type;
            extension_type_with_never_send.should_send = s2n_extension_never_send;

            EXPECT_SUCCESS(s2n_extension_send(&extension_type_with_never_send, &conn, &stuffer));
            EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));
            /* cppcheck-suppress sizeofDivisionMemfunc */
            EXPECT_BITFIELD_CLEAR(conn.extension_requests_sent);
        };

        /* "send" errors */
        {
            struct s2n_connection conn = { 0 };
            struct s2n_stuffer stuffer = { 0 };
            s2n_stuffer_alloc(&stuffer, S2N_TEST_DATA_LEN);

            s2n_extension_type extension_type_with_failure = test_extension_type;
            extension_type_with_failure.send = s2n_extension_send_unimplemented;

            EXPECT_FAILURE_WITH_ERRNO(s2n_extension_send(&extension_type_with_failure, &conn, &stuffer), S2N_ERR_UNIMPLEMENTED);
            /* cppcheck-suppress sizeofDivisionMemfunc */
            EXPECT_BITFIELD_CLEAR(conn.extension_requests_sent);

            s2n_stuffer_free(&stuffer);
        };

        /* "send" writes more data than will fit in the extension size */
        {
            struct s2n_connection conn = { 0 };
            struct s2n_stuffer stuffer = { 0 };
            s2n_stuffer_growable_alloc(&stuffer, 0);

            s2n_extension_type extension_type_with_too_much_data = test_extension_type;
            extension_type_with_too_much_data.send = test_send_too_much_data;

            EXPECT_FAILURE_WITH_ERRNO(s2n_extension_send(&extension_type_with_too_much_data, &conn, &stuffer),
                    S2N_ERR_SIZE_MISMATCH);

            s2n_stuffer_free(&stuffer);
        };
    };

    /* Test s2n_extension_is_missing */
    {
        /* null check tests */
        {
            struct s2n_connection conn = { 0 };

            EXPECT_FAILURE(s2n_extension_is_missing(NULL, &conn));
            EXPECT_FAILURE(s2n_extension_is_missing(&test_extension_type, NULL));

            s2n_extension_type extension_type_with_null_if_missing = test_extension_type;
            extension_type_with_null_if_missing.if_missing = NULL;
            EXPECT_FAILURE(s2n_extension_is_missing(&extension_type_with_null_if_missing, &conn));
        };

        /* Test no-op if_missing */
        {
            struct s2n_connection conn = { 0 };

            s2n_extension_type extension_type_with_noop_if_missing = test_extension_type;
            extension_type_with_noop_if_missing.if_missing = s2n_extension_noop_if_missing;

            extension_type_with_noop_if_missing.is_response = false;
            EXPECT_SUCCESS(s2n_extension_is_missing(&extension_type_with_noop_if_missing, &conn));

            extension_type_with_noop_if_missing.is_response = true;
            EXPECT_SUCCESS(s2n_extension_is_missing(&extension_type_with_noop_if_missing, &conn));

            S2N_CBIT_SET(conn.extension_requests_sent, test_extension_id);
            EXPECT_SUCCESS(s2n_extension_is_missing(&extension_type_with_noop_if_missing, &conn));
        };

        /* Test error if_missing */
        {
            struct s2n_connection conn = { 0 };

            s2n_extension_type extension_type_with_error_if_missing = test_extension_type;
            extension_type_with_error_if_missing.if_missing = s2n_extension_error_if_missing;

            /* Should fail for a request */
            extension_type_with_error_if_missing.is_response = false;
            EXPECT_FAILURE_WITH_ERRNO(s2n_extension_is_missing(&extension_type_with_error_if_missing, &conn),
                    S2N_ERR_MISSING_EXTENSION);

            /* Should succeed for a response without a corresponding request.
             * We don't expect to receive the response, so it isn't considered missing. */
            extension_type_with_error_if_missing.is_response = true;
            EXPECT_SUCCESS(s2n_extension_is_missing(&extension_type_with_error_if_missing, &conn));

            /* Should fail for a response with a corresponding request */
            S2N_CBIT_SET(conn.extension_requests_sent, test_extension_id);
            EXPECT_FAILURE_WITH_ERRNO(s2n_extension_is_missing(&extension_type_with_error_if_missing, &conn),
                    S2N_ERR_MISSING_EXTENSION);
        };
    };

    /* Test minimum_version field */
    {
        EXPECT_SUCCESS(s2n_reset_tls13_in_test());

        s2n_extension_type test_extension_type_with_min = test_extension_type;
        test_extension_type_with_min.minimum_version = S2N_TLS13;

        /* If any of these methods actually execute, they will fail */
        test_extension_type_with_min.if_missing = s2n_extension_error_if_missing;
        test_extension_type_with_min.send = s2n_extension_send_unimplemented;
        test_extension_type_with_min.recv = s2n_extension_recv_unimplemented;

        struct s2n_connection conn = { 0 };

        /* Does not meet minimum.
         * No methods execute, so no errors. */
        {
            conn.actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_extension_recv(&test_extension_type_with_min, &conn, NULL));
            EXPECT_SUCCESS(s2n_extension_send(&test_extension_type_with_min, &conn, NULL));
            EXPECT_SUCCESS(s2n_extension_is_missing(&test_extension_type_with_min, &conn));
        };

        /* Meets minimum.
         * All methods execute, so all errors. */
        {
            conn.actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE(s2n_extension_recv(&test_extension_type_with_min, &conn, NULL));
            EXPECT_FAILURE(s2n_extension_send(&test_extension_type_with_min, &conn, NULL));
            EXPECT_FAILURE(s2n_extension_is_missing(&test_extension_type_with_min, &conn));
        };

        /* Ensure that no extension type sets nonzero minimum_version < S2N_TLS13.
         * Currently, nonzero minimum_version < S2N_TLS13 will not necessarily work because earlier versions
         * do not set their protocol version until after processing all extensions.
         */
        {
            s2n_extension_type_list *list = NULL;
            const s2n_extension_type *type = NULL;
            for (s2n_extension_list_id list_i = 0; list_i < S2N_EXTENSION_LIST_IDS_COUNT; list_i++) {
                EXPECT_SUCCESS(s2n_extension_type_list_get(list_i, &list));
                EXPECT_NOT_NULL(list);
                for (size_t ext_i = 0; ext_i < list->count; ext_i++) {
                    type = list->extension_types[ext_i];
                    EXPECT_TRUE(type->minimum_version == 0 || type->minimum_version >= S2N_TLS13);
                }
            }
        }

        /* Functional test: minimum-TLS1.3 extensions only used for TLS1.3 */
        {
            struct s2n_cert_chain_and_key *cert_chain = NULL;
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&cert_chain,
                    S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

            struct s2n_config *test_all_config = s2n_config_new();
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(test_all_config, cert_chain));
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(test_all_config));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(test_all_config, "test_all"));

            uint16_t key_shares_id = s2n_extension_iana_value_to_id(TLS_EXTENSION_KEY_SHARE);

            /* Both TLS1.3 */
            if (s2n_is_tls13_fully_supported()) {
                struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, test_all_config));

                struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
                EXPECT_NOT_NULL(server_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, test_all_config));

                struct s2n_test_io_pair io_pair = { 0 };
                EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
                EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

                /* All expected CLIENT_HELLO extensions sent and received */
                EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_HELLO));
                EXPECT_TRUE(S2N_CBIT_TEST(client_conn->extension_requests_sent, key_shares_id));
                EXPECT_TRUE(S2N_CBIT_TEST(server_conn->extension_requests_received, key_shares_id));

                /* All expected SERVER_HELLO extensions received */
                EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, ENCRYPTED_EXTENSIONS));
                EXPECT_TRUE(S2N_CBIT_TEST(client_conn->extension_responses_received, key_shares_id));

                EXPECT_SUCCESS(s2n_connection_free(client_conn));
                EXPECT_SUCCESS(s2n_connection_free(server_conn));
            }

            /* Client TLS1.2 */
            {
                struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, test_all_config));
                EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "test_all_tls12"));

                struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
                EXPECT_NOT_NULL(server_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, test_all_config));

                struct s2n_test_io_pair io_pair = { 0 };
                EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
                EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

                /* No expected CLIENT_HELLO extensions sent and received */
                EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_HELLO));
                EXPECT_FALSE(S2N_CBIT_TEST(client_conn->extension_requests_sent, key_shares_id));
                EXPECT_FALSE(S2N_CBIT_TEST(server_conn->extension_requests_received, key_shares_id));

                /* No expected SERVER_HELLO extensions sent and received */
                EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, ENCRYPTED_EXTENSIONS));
                EXPECT_FALSE(S2N_CBIT_TEST(client_conn->extension_requests_received, key_shares_id));
                EXPECT_FALSE(S2N_CBIT_TEST(server_conn->extension_requests_sent, key_shares_id));

                EXPECT_SUCCESS(s2n_connection_free(client_conn));
                EXPECT_SUCCESS(s2n_connection_free(server_conn));
            };

            /* Client TLS 1.3 with Server TLS1.2 */
            if (s2n_is_tls13_fully_supported()) {
                struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, test_all_config));

                struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
                EXPECT_NOT_NULL(server_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, test_all_config));
                EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "test_all_tls12"));

                struct s2n_test_io_pair io_pair = { 0 };
                EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
                EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

                /* Expected CLIENT_HELLO extensions sent, but not received */
                EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_HELLO));
                EXPECT_TRUE(S2N_CBIT_TEST(client_conn->extension_requests_sent, key_shares_id));
                EXPECT_FALSE(S2N_CBIT_TEST(server_conn->extension_requests_received, key_shares_id));

                /* No expected SERVER_HELLO extensions sent and received */
                EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, ENCRYPTED_EXTENSIONS));
                EXPECT_FALSE(S2N_CBIT_TEST(client_conn->extension_requests_received, key_shares_id));
                EXPECT_FALSE(S2N_CBIT_TEST(server_conn->extension_requests_sent, key_shares_id));

                EXPECT_SUCCESS(s2n_connection_free(client_conn));
                EXPECT_SUCCESS(s2n_connection_free(server_conn));
            }

            EXPECT_SUCCESS(s2n_config_free(test_all_config));
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(cert_chain));
        };
    };

    END_TEST();
}
