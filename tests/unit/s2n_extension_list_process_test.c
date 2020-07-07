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
#include "tls/extensions/s2n_server_max_fragment_length.h"
#include "tls/extensions/s2n_server_server_name.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"

#define SET_PARSED_EXTENSION(list, entry) do {                                              \
    s2n_extension_type_id id;                                                               \
    EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(entry.extension_type, &id));    \
    list.parsed_extensions[id] = entry;                                                     \
} while(0)

static int s2n_setup_test_parsed_extension(const s2n_extension_type *extension_type,
        s2n_parsed_extension *parsed_extension, struct s2n_connection *conn, struct s2n_stuffer *stuffer)
{
    parsed_extension->extension_type = extension_type->iana_value;

    GUARD(extension_type->send(conn, stuffer));
    uint16_t extension_size = s2n_stuffer_data_available(stuffer);
    GUARD(s2n_blob_init(&parsed_extension->extension, s2n_stuffer_raw_read(stuffer, extension_size), extension_size));

    return S2N_SUCCESS;
}

static bool received_flag = false;
static int s2n_extension_test_recv(struct s2n_connection *conn, struct s2n_stuffer *stuffer)
{
    received_flag = true;
    return S2N_SUCCESS;
}

int main()
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    /* Test s2n_extension_process */
    {
        uint8_t extension_data[] = "data";
        struct s2n_blob extension_blob;
        EXPECT_SUCCESS(s2n_blob_init(&extension_blob, extension_data, sizeof(extension_data)));

        const s2n_extension_type test_extension_type = {
                .iana_value = TLS_EXTENSION_SUPPORTED_VERSIONS,
                .is_response = false,
                .should_send = s2n_extension_never_send,
                .send = s2n_extension_send_unimplemented,
                .recv = s2n_extension_test_recv,
                .if_missing = s2n_extension_noop_if_missing,
        };

        s2n_extension_type_id test_extension_type_internal_id;
        EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(test_extension_type.iana_value,
                &test_extension_type_internal_id));

        /* Safety checks */
        {
            struct s2n_connection conn = { 0 };
            s2n_parsed_extensions_list parsed_extension_list = { 0 };
            const s2n_extension_type extension_type = { 0 };

            EXPECT_FAILURE(s2n_extension_process(NULL, &conn, &parsed_extension_list));
            EXPECT_FAILURE(s2n_extension_process(&extension_type, NULL, &parsed_extension_list));
            EXPECT_FAILURE(s2n_extension_process(&extension_type, &conn, NULL));
        }

        /* Successfully process a basic parsed_extension */
        {
            s2n_parsed_extensions_list parsed_extension_list = { 0 };
            const s2n_parsed_extension test_parsed_extension = {
                  .extension_type = test_extension_type.iana_value,
                  .extension = extension_blob,
            };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            SET_PARSED_EXTENSION(parsed_extension_list, test_parsed_extension);

            received_flag = false;
            EXPECT_SUCCESS(s2n_extension_process(&test_extension_type, conn, &parsed_extension_list));

            EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);
            EXPECT_TRUE(received_flag);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Successfully process an empty parsed_extension */
        {
            s2n_parsed_extensions_list parsed_extension_list = { 0 };
            struct s2n_blob empty_blob = extension_blob;
            empty_blob.size = 0;
            const s2n_parsed_extension test_parsed_extension = {
                  .extension_type = test_extension_type.iana_value,
                  .extension = empty_blob,
            };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            SET_PARSED_EXTENSION(parsed_extension_list, test_parsed_extension);

            received_flag = false;
            EXPECT_SUCCESS(s2n_extension_process(&test_extension_type, conn, &parsed_extension_list));

            EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);
            EXPECT_TRUE(received_flag);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Fail if parsed_extension indexed incorrectly */
        {
            s2n_parsed_extensions_list parsed_extension_list = { 0 };
            const s2n_parsed_extension test_parsed_extension = {
                  .extension_type = test_extension_type.iana_value - 1,
                  .extension = extension_blob,
            };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            parsed_extension_list.parsed_extensions[test_extension_type_internal_id] = test_parsed_extension;

            received_flag = false;
            EXPECT_FAILURE_WITH_ERRNO(s2n_extension_process(&test_extension_type, conn, &parsed_extension_list),
                    S2N_ERR_INVALID_PARSED_EXTENSIONS);

            EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);
            EXPECT_FALSE(received_flag);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* If no parsed_extension found for extension type */
        {
            /* Fail if extension type is required */
            {
                s2n_parsed_extensions_list parsed_extension_list = { 0 };

                s2n_extension_type test_required_extension_type = test_extension_type;
                test_required_extension_type.if_missing = s2n_extension_error_if_missing;

                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

                received_flag = false;
                EXPECT_FAILURE_WITH_ERRNO(s2n_extension_process(&test_required_extension_type, conn, &parsed_extension_list),
                        S2N_ERR_MISSING_EXTENSION);

                EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);
                EXPECT_FALSE(received_flag);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }

            /* Succeed (but don't call recv) if extension type is optional */
            {
                s2n_parsed_extensions_list parsed_extension_list = { 0 };

                s2n_extension_type test_optional_extension_type = test_extension_type;
                test_optional_extension_type.if_missing = s2n_extension_noop_if_missing;

                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

                received_flag = false;
                EXPECT_SUCCESS(s2n_extension_process(&test_optional_extension_type, conn, &parsed_extension_list));

                EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);
                EXPECT_FALSE(received_flag);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }
        }
    }

    /* Test s2n_extension_list_process */
    {
        s2n_parsed_extension test_empty_parsed_extension = { 0 };
        s2n_parsed_extension test_parsed_extension = { 0 };

        DEFER_CLEANUP(struct s2n_stuffer extension_data_stuffer, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_alloc(&extension_data_stuffer, 100));

        /* Set up parsed_extensions for simple real extensions */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            EXPECT_SUCCESS(s2n_setup_test_parsed_extension(&s2n_server_server_name_extension,
                    &test_empty_parsed_extension, conn, &extension_data_stuffer));
            EXPECT_EQUAL(test_empty_parsed_extension.extension.size, 0);

            EXPECT_SUCCESS(s2n_setup_test_parsed_extension(&s2n_server_max_fragment_length_extension,
                    &test_parsed_extension, conn, &extension_data_stuffer));
            EXPECT_NOT_EQUAL(test_parsed_extension.extension.size, 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Safety checks */
        {
            struct s2n_connection conn = { 0 };
            s2n_parsed_extensions_list parsed_extension_list = { 0 };

            EXPECT_FAILURE(s2n_extension_list_process(0, NULL, &parsed_extension_list));
            EXPECT_FAILURE(s2n_extension_list_process(0, &conn, NULL));
            EXPECT_FAILURE(s2n_extension_list_process(-1, &conn, &parsed_extension_list));
        }

        /* Process a single parsed_extension */
        {
            s2n_parsed_extensions_list parsed_extension_list = { 0 };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));

            SET_PARSED_EXTENSION(parsed_extension_list, test_empty_parsed_extension);

            conn->server_name_used = false;
            EXPECT_SUCCESS(s2n_extension_list_process(S2N_EXTENSION_LIST_ENCRYPTED_EXTENSIONS,
                    conn, &parsed_extension_list));

            EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);
            EXPECT_TRUE(conn->server_name_used);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Process several parsed_extensions */
        {
            s2n_parsed_extensions_list parsed_extension_list = { 0 };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));

            SET_PARSED_EXTENSION(parsed_extension_list, test_empty_parsed_extension);
            SET_PARSED_EXTENSION(parsed_extension_list, test_parsed_extension);

            conn->server_name_used = false;
            EXPECT_SUCCESS(s2n_extension_list_process(S2N_EXTENSION_LIST_ENCRYPTED_EXTENSIONS,
                    conn, &parsed_extension_list));

            EXPECT_PARSED_EXTENSION_LIST_EMPTY(parsed_extension_list);
            EXPECT_TRUE(conn->server_name_used);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Skips on unexpected parsed_extension */
        {
            s2n_parsed_extensions_list parsed_extension_list = { 0 };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));

            SET_PARSED_EXTENSION(parsed_extension_list, test_empty_parsed_extension);

            conn->server_name_used = false;
            EXPECT_SUCCESS(s2n_extension_list_process(S2N_EXTENSION_LIST_EMPTY, conn, &parsed_extension_list));

            EXPECT_PARSED_EXTENSION_LIST_NOT_EMPTY(parsed_extension_list);
            EXPECT_FALSE(conn->server_name_used);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    END_TEST();
}
