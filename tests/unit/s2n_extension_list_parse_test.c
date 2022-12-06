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
#include "tls/extensions/s2n_extension_list.h"
#include "tls/extensions/s2n_extension_type.h"

#define S2N_UNKNOWN_EXTENSION_IANA 65280 /* Grease value: https://tools.ietf.org/html/rfc8701 */

const uint8_t test_data[] = "Test Data";
const uint8_t other_test_data[] = "Different Test Data";

static int s2n_extension_send_test_data(struct s2n_connection *conn, struct s2n_stuffer *stuffer)
{
    return s2n_stuffer_write_bytes(stuffer, test_data, sizeof(test_data));
}

static int s2n_extension_send_other_test_data(struct s2n_connection *conn, struct s2n_stuffer *stuffer)
{
    return s2n_stuffer_write_bytes(stuffer, other_test_data, sizeof(other_test_data));
}

static int s2n_extension_send_no_data(struct s2n_connection *conn, struct s2n_stuffer *stuffer)
{
    return S2N_SUCCESS;
}

const s2n_extension_type test_extension = {
    .iana_value = TLS_EXTENSION_SUPPORTED_VERSIONS,
    .is_response = false,
    .send = s2n_extension_send_test_data,
    .recv = s2n_extension_recv_unimplemented,
    .should_send = s2n_extension_always_send,
    .if_missing = s2n_extension_noop_if_missing,
};

#define EXPECT_PARSED_EXTENSION_EQUAL(list, type, d, n)                          \
    do {                                                                         \
        s2n_extension_type_id id;                                                \
        EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(type, &id));     \
        EXPECT_NOT_NULL(list.parsed_extensions[id].extension.data);              \
        EXPECT_EQUAL(list.parsed_extensions[id].extension.size, n);              \
        EXPECT_BYTEARRAY_EQUAL(list.parsed_extensions[id].extension.data, d, n); \
    } while (0)

#define EXPECT_RAW_EQUAL(list, stuffer)                                \
    EXPECT_EQUAL(list.raw.data, stuffer.blob.data + sizeof(uint16_t)); \
    EXPECT_EQUAL(list.raw.size, stuffer.high_water_mark - sizeof(uint16_t))

#define CLEAR_PARSED_EXTENSION(list, type)                                   \
    do {                                                                     \
        s2n_extension_type_id id;                                            \
        EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(type, &id)); \
        list.parsed_extensions[id] = EMPTY_PARSED_EXTENSIONS[0];             \
    } while (0)

int main()
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    s2n_extension_type empty_test_extension = test_extension;
    empty_test_extension.send = s2n_extension_send_no_data;

    struct s2n_connection *conn;
    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

    /* Safety checks */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };

        EXPECT_FAILURE(s2n_extension_list_parse(NULL, &parsed_extension_list));
        EXPECT_FAILURE(s2n_extension_list_parse(&stuffer, NULL));
    };

    /* Test that parse clears existing parsed_extensions */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1));

        parsed_extension_list.parsed_extensions[0].extension_type = 0xFF;
        parsed_extension_list.parsed_extensions[S2N_PARSED_EXTENSIONS_COUNT - 1].extension_type = 0xFF;
        EXPECT_PARSED_EXTENSION_LIST_NOT_EMPTY(parsed_extension_list);

        EXPECT_SUCCESS(s2n_extension_list_parse(&stuffer, &parsed_extension_list));

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
        EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);

        EXPECT_EQUAL(parsed_extension_list.raw.data, stuffer.blob.data);
        EXPECT_EQUAL(parsed_extension_list.raw.size, 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test parse empty extension list - no extension list size */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1));

        EXPECT_SUCCESS(s2n_extension_list_parse(&stuffer, &parsed_extension_list));

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
        EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);

        EXPECT_EQUAL(parsed_extension_list.raw.data, stuffer.blob.data);
        EXPECT_EQUAL(parsed_extension_list.raw.size, 0);
        EXPECT_EQUAL(parsed_extension_list.count, 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test parse empty extension list - with extension list size */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Write zero size */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, 0));

        EXPECT_SUCCESS(s2n_extension_list_parse(&stuffer, &parsed_extension_list));

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
        EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);
        EXPECT_RAW_EQUAL(parsed_extension_list, stuffer);
        EXPECT_EQUAL(parsed_extension_list.raw.size, 0);
        EXPECT_EQUAL(parsed_extension_list.count, 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test parse with insufficient data to match extension list size */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, 100));

        EXPECT_FAILURE_WITH_ERRNO(s2n_extension_list_parse(&stuffer, &parsed_extension_list),
                S2N_ERR_BAD_MESSAGE);

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
        EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test parse with insufficient data for even one extension */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Extension list size */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, sizeof(uint16_t) - 1));
        /* One less byte than the extension type takes  */
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&stuffer, sizeof(uint16_t) - 1));

        EXPECT_FAILURE_WITH_ERRNO(s2n_extension_list_parse(&stuffer, &parsed_extension_list),
                S2N_ERR_BAD_MESSAGE);

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
        EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test parse single extension in list */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Reserve size */
        struct s2n_stuffer_reservation extension_list_size = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &extension_list_size));
        /* Write extensions */
        EXPECT_SUCCESS(s2n_extension_send(&test_extension, conn, &stuffer));
        /* Check / write size */
        EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) > extension_list_size.length);
        EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&extension_list_size));

        EXPECT_SUCCESS(s2n_extension_list_parse(&stuffer, &parsed_extension_list));

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
        EXPECT_PARSED_EXTENSION_LIST_NOT_EMPTY(parsed_extension_list);
        EXPECT_RAW_EQUAL(parsed_extension_list, stuffer);

        EXPECT_PARSED_EXTENSION_EQUAL(parsed_extension_list, test_extension.iana_value, test_data, sizeof(test_data));
        EXPECT_EQUAL(parsed_extension_list.count, 1);
        CLEAR_PARSED_EXTENSION(parsed_extension_list, test_extension.iana_value);
        EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test parse single extension in list - malformed extension size */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Reserve size */
        struct s2n_stuffer_reservation extension_list_size = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &extension_list_size));
        /* Write extensions */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, 100));
        /* Check / write size */
        EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) > extension_list_size.length);
        EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&extension_list_size));

        EXPECT_FAILURE_WITH_ERRNO(s2n_extension_list_parse(&stuffer, &parsed_extension_list),
                S2N_ERR_BAD_MESSAGE);

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
        EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);
        EXPECT_RAW_EQUAL(parsed_extension_list, stuffer);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test parse single extension in list - extension is empty */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Reserve size */
        struct s2n_stuffer_reservation extension_list_size = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &extension_list_size));
        /* Write extensions */
        EXPECT_SUCCESS(s2n_extension_send(&empty_test_extension, conn, &stuffer));
        /* Check / write size */
        EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) > extension_list_size.length);
        EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&extension_list_size));

        EXPECT_SUCCESS(s2n_extension_list_parse(&stuffer, &parsed_extension_list));

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
        EXPECT_EQUAL(parsed_extension_list.count, 1);
        EXPECT_PARSED_EXTENSION_LIST_NOT_EMPTY(parsed_extension_list);
        EXPECT_RAW_EQUAL(parsed_extension_list, stuffer);

        EXPECT_PARSED_EXTENSION_EQUAL(parsed_extension_list, test_extension.iana_value, test_data, 0);
        CLEAR_PARSED_EXTENSION(parsed_extension_list, test_extension.iana_value);
        EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test parse single extension in list - ignore unknown extensions */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Reserve size */
        struct s2n_stuffer_reservation extension_list_size = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &extension_list_size));
        /* Write extension - use grease value as type */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, S2N_UNKNOWN_EXTENSION_IANA));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, 0));
        /* Check / write size */
        EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) > extension_list_size.length);
        EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&extension_list_size));

        EXPECT_SUCCESS(s2n_extension_list_parse(&stuffer, &parsed_extension_list));

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
        EXPECT_EQUAL(parsed_extension_list.count, 0);
        EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);
        EXPECT_RAW_EQUAL(parsed_extension_list, stuffer);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test error on duplicate extensions */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Reserve size */
        struct s2n_stuffer_reservation extension_list_size = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &extension_list_size));
        /* Write extensions */
        EXPECT_SUCCESS(s2n_extension_send(&test_extension, conn, &stuffer));
        EXPECT_SUCCESS(s2n_extension_send(&test_extension, conn, &stuffer));
        /* Check / write size */
        EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) > extension_list_size.length);
        EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&extension_list_size));

        EXPECT_FAILURE_WITH_ERRNO(s2n_extension_list_parse(&stuffer, &parsed_extension_list),
                S2N_ERR_DUPLICATE_EXTENSION);
        EXPECT_RAW_EQUAL(parsed_extension_list, stuffer);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test error on duplicate extensions - extensions are empty */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Reserve size */
        struct s2n_stuffer_reservation extension_list_size = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &extension_list_size));
        /* Write extensions */
        EXPECT_SUCCESS(s2n_extension_send(&empty_test_extension, conn, &stuffer));
        EXPECT_SUCCESS(s2n_extension_send(&empty_test_extension, conn, &stuffer));
        /* Check / write size */
        EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) > extension_list_size.length);
        EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&extension_list_size));

        EXPECT_FAILURE_WITH_ERRNO(s2n_extension_list_parse(&stuffer, &parsed_extension_list),
                S2N_ERR_DUPLICATE_EXTENSION);
        EXPECT_RAW_EQUAL(parsed_extension_list, stuffer);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test parse multiple extensions */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        s2n_extension_type test_extension_2 = empty_test_extension;
        test_extension_2.iana_value = TLS_EXTENSION_SIGNATURE_ALGORITHMS;
        s2n_extension_type test_extension_3 = test_extension;
        test_extension_3.iana_value = TLS_EXTENSION_ALPN;
        test_extension_3.send = s2n_extension_send_other_test_data;

        /* Reserve size */
        struct s2n_stuffer_reservation extension_list_size = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &extension_list_size));
        /* Write extensions */
        EXPECT_SUCCESS(s2n_extension_send(&test_extension, conn, &stuffer));
        EXPECT_SUCCESS(s2n_extension_send(&test_extension_2, conn, &stuffer));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, S2N_UNKNOWN_EXTENSION_IANA));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, 0));
        EXPECT_SUCCESS(s2n_extension_send(&test_extension_3, conn, &stuffer));
        /* Check / write size */
        EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) > extension_list_size.length);
        EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&extension_list_size));

        EXPECT_SUCCESS(s2n_extension_list_parse(&stuffer, &parsed_extension_list));

        EXPECT_PARSED_EXTENSION_EQUAL(parsed_extension_list, test_extension.iana_value, test_data, sizeof(test_data));
        EXPECT_PARSED_EXTENSION_EQUAL(parsed_extension_list, test_extension_2.iana_value, test_data, 0);
        EXPECT_PARSED_EXTENSION_EQUAL(parsed_extension_list, test_extension_3.iana_value, other_test_data, sizeof(other_test_data));
        EXPECT_RAW_EQUAL(parsed_extension_list, stuffer);
        EXPECT_EQUAL(parsed_extension_list.count, 3);

        CLEAR_PARSED_EXTENSION(parsed_extension_list, test_extension.iana_value);
        CLEAR_PARSED_EXTENSION(parsed_extension_list, test_extension_2.iana_value);
        CLEAR_PARSED_EXTENSION(parsed_extension_list, test_extension_3.iana_value);
        EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test parsed extensions assigned correct indexes */
    {
        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        s2n_extension_type test_extension_2 = test_extension;
        test_extension_2.iana_value = TLS_EXTENSION_SIGNATURE_ALGORITHMS;
        s2n_extension_type test_extension_3 = test_extension;
        test_extension_3.iana_value = TLS_EXTENSION_ALPN;

        /* Reserve size */
        struct s2n_stuffer_reservation extension_list_size = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &extension_list_size));
        /* Write extensions */
        EXPECT_SUCCESS(s2n_extension_send(&test_extension, conn, &stuffer));
        EXPECT_SUCCESS(s2n_extension_send(&test_extension_2, conn, &stuffer));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, S2N_UNKNOWN_EXTENSION_IANA));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, 0));
        EXPECT_SUCCESS(s2n_extension_send(&test_extension_3, conn, &stuffer));
        /* Check / write size */
        EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) > extension_list_size.length);
        EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&extension_list_size));

        EXPECT_SUCCESS(s2n_extension_list_parse(&stuffer, &parsed_extension_list));

        uint16_t expected_order[] = { test_extension.iana_value, test_extension_2.iana_value, test_extension_3.iana_value };
        for (size_t i = 0; i < s2n_array_len(expected_order); i++) {
            s2n_extension_type_id id;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(expected_order[i], &id));
            EXPECT_EQUAL(parsed_extension_list.parsed_extensions[id].wire_index, i);
        }
        EXPECT_EQUAL(parsed_extension_list.count, 3);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    EXPECT_SUCCESS(s2n_connection_free(conn));

    END_TEST();
}
