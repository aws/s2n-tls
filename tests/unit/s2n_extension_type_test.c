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
#include "tls/s2n_tls.h"

#define S2N_TEST_DATA_LEN 20

extern s2n_extension_type_id s2n_supported_extensions_count;
extern uint16_t s2n_supported_extensions[];

static int test_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    return s2n_stuffer_skip_write(out, S2N_TEST_DATA_LEN);
}

static int test_recv(struct s2n_connection *conn, struct s2n_stuffer *in)
{
    return S2N_SUCCESS;
}

s2n_extension_type test_extension_type = {
        .iana_value = TLS_EXTENSION_SUPPORTED_VERSIONS,
        .send = test_send,
        .recv = test_recv
};

int main()
{
    BEGIN_TEST();

    /* Test common implementations of methods */
    {
        /* Test common implementations for send */
        EXPECT_FAILURE_WITH_ERRNO(s2n_extension_send_unimplemented(NULL, NULL), S2N_ERR_UNIMPLEMENTED);

        /* Test common implementations for recv */
        EXPECT_FAILURE_WITH_ERRNO(s2n_extension_recv_unimplemented(NULL, NULL), S2N_ERR_UNIMPLEMENTED);

        /* Test common implementations for should_send */
        EXPECT_EQUAL(s2n_extension_always_send(NULL), S2N_SUCCESS);
        EXPECT_EQUAL(s2n_extension_never_send(NULL), S2N_FAILURE);

        /* Test common implementations for should_recv */
        uint8_t is_required = 0;
        EXPECT_EQUAL(s2n_extension_always_recv(NULL, &is_required), S2N_SUCCESS);
        EXPECT_TRUE(is_required);
        EXPECT_EQUAL(s2n_extension_may_recv(NULL, &is_required), S2N_SUCCESS);
        EXPECT_FALSE(is_required);
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
        EXPECT_EQUAL(s2n_extension_iana_value_to_id(666), s2n_unsupported_extension);

        /* Every supported extension can be handled */
        for (int i = 0; i < s2n_supported_extensions_count; i++) {
            EXPECT_EQUAL(s2n_extension_iana_value_to_id(s2n_supported_extensions[i]), i);
        }
    }

    struct s2n_connection conn;
    struct s2n_stuffer stuffer;

    /* Test s2n_extension_recv */
    {
        /* null check tests */
        EXPECT_FAILURE(s2n_extension_recv(NULL, &conn, &stuffer));
        EXPECT_FAILURE(s2n_extension_recv(&test_extension_type, &conn, NULL));
        EXPECT_FAILURE(s2n_extension_recv(&test_extension_type, NULL, &stuffer));

        /* happy case */
        EXPECT_SUCCESS(s2n_extension_recv(&test_extension_type, &conn, &stuffer));
    }

    /* Test s2n_extension_send */
    {
        s2n_stuffer_alloc(&stuffer, S2N_TEST_DATA_LEN*2);

        /* null check tests */
        EXPECT_FAILURE(s2n_extension_send(NULL, &conn, &stuffer));
        EXPECT_FAILURE(s2n_extension_send(&test_extension_type, &conn, NULL));
        EXPECT_FAILURE(s2n_extension_send(&test_extension_type, NULL, &stuffer));

        EXPECT_SUCCESS(s2n_extension_send(&test_extension_type, &conn, &stuffer));

        /* writes iana_value */
        uint16_t iana_value;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &iana_value));
        EXPECT_EQUAL(iana_value, test_extension_type.iana_value);

        /* writes length */
        uint16_t length;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &length));
        EXPECT_EQUAL(length, s2n_stuffer_data_available(&stuffer));
        EXPECT_EQUAL(length, S2N_TEST_DATA_LEN);

        s2n_stuffer_free(&stuffer);
    }

    END_TEST();
}
