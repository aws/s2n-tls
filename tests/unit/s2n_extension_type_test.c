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

#include "tls/extensions/s2n_extension_type.h"
#include "utils/s2n_bitmap.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"

#define S2N_TEST_DATA_LEN 20

#define EXPECT_BITFIELD_CLEAR(field) EXPECT_BYTEARRAY_EQUAL((field), &empty_bitfield, S2N_SUPPORTED_EXTENSIONS_BITFIELD_LEN)

s2n_extension_type_id s2n_extension_iana_value_to_id(uint16_t iana_value);

const s2n_extension_bitfield empty_bitfield = { 0 };

static int test_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    return s2n_stuffer_skip_write(out, S2N_TEST_DATA_LEN);
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
        }

        /* Test common implementations for if_missing */
        EXPECT_FAILURE_WITH_ERRNO(s2n_extension_error_if_missing(NULL), S2N_ERR_MISSING_EXTENSION);
        EXPECT_SUCCESS(s2n_extension_noop_if_missing(NULL));
    }

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
        for (int i = 0; i < S2N_SUPPORTED_EXTENSIONS_COUNT; i++) {
            EXPECT_EQUAL(s2n_extension_iana_value_to_id(s2n_supported_extensions[i]), i);
        }
    }

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
    }

    /* Test bitfield behavior */
    {
        s2n_extension_bitfield test_bitfield = { 0 };
        for (int i = 0; i < S2N_SUPPORTED_EXTENSIONS_COUNT; i++) {
            uint16_t iana = s2n_supported_extensions[i];
            s2n_extension_type_id id = s2n_extension_iana_value_to_id(iana);

            EXPECT_FALSE(S2N_CBIT_TEST(test_bitfield, id));
            S2N_CBIT_SET(test_bitfield, id);
            EXPECT_TRUE(S2N_CBIT_TEST(test_bitfield, id));
            S2N_CBIT_CLR(test_bitfield, id);
            EXPECT_FALSE(S2N_CBIT_TEST(test_bitfield, id));
        }
    }

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
        }

        /* request extension */
        {
            struct s2n_connection conn = { 0 };
            s2n_extension_type request_extension_type = test_extension_type;
            request_extension_type.is_response = false;

            /* Succeeds and sets request flag */
            EXPECT_SUCCESS(s2n_extension_recv(&request_extension_type, &conn, &stuffer));
            EXPECT_TRUE(S2N_CBIT_TEST(conn.extension_requests_received, test_extension_id));
        }

        /* response extension */
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
        }

        /* "recv" errors */
        {
            struct s2n_connection conn = { 0 };
            s2n_extension_type extension_type_with_failure = test_extension_type;
            extension_type_with_failure.recv = s2n_extension_recv_unimplemented;

            EXPECT_FAILURE_WITH_ERRNO(s2n_extension_recv(&extension_type_with_failure, &conn, &stuffer), S2N_ERR_UNIMPLEMENTED);
            /* cppcheck-suppress sizeofDivisionMemfunc */
            EXPECT_BITFIELD_CLEAR(conn.extension_requests_received);
        }
    }

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
        }

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
        }

        /* response extension */
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
        }

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
        }

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
        }
    }

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
        }

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
        }

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
        }
    }

    END_TEST();
}
