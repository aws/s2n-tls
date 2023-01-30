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
#include "tls/extensions/s2n_client_supported_versions.h"
#include "tls/extensions/s2n_extension_list.h"
#include "tls/extensions/s2n_extension_type_lists.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    /* Safety checks */
    {
        struct s2n_connection conn = { 0 };
        struct s2n_stuffer stuffer = { 0 };

        EXPECT_FAILURE(s2n_extension_list_send(0, NULL, &stuffer));
        EXPECT_FAILURE(s2n_extension_list_send(0, &conn, NULL));
        EXPECT_FAILURE(s2n_extension_list_send(-1, &conn, &stuffer));
    };

    /* Writes just size if extension type list empty */
    {
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_EMPTY, conn, &stuffer));

        uint16_t extension_list_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &extension_list_size));
        EXPECT_EQUAL(extension_list_size, s2n_stuffer_data_available(&stuffer));
        EXPECT_EQUAL(extension_list_size, 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Send performs basic, non-zero write */
    {
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_CLIENT_HELLO, conn, &stuffer));

        uint16_t extension_list_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &extension_list_size));
        EXPECT_EQUAL(extension_list_size, s2n_stuffer_data_available(&stuffer));
        EXPECT_NOT_EQUAL(extension_list_size, 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Write empty list */
    {
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        /* S2N_EXTENSION_LIST_CERTIFICATE only sends responses, and we haven't received any requests.
         * Therefore, it should write an empty extensions list. */
        EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_CERTIFICATE, conn, &stuffer));

        uint16_t extension_list_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &extension_list_size));
        EXPECT_EQUAL(extension_list_size, s2n_stuffer_data_available(&stuffer));
        EXPECT_EQUAL(extension_list_size, 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Send writes valid supported_versions extension */
    {
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_CLIENT_HELLO, client_conn, &stuffer));

        /* Skip list size - already tested */
        EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, sizeof(uint16_t)));

        uint16_t first_extension_type;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &first_extension_type));
        EXPECT_EQUAL(first_extension_type, TLS_EXTENSION_SUPPORTED_VERSIONS);

        uint16_t first_extension_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &first_extension_size));
        EXPECT_NOT_EQUAL(first_extension_size, 0);

        struct s2n_stuffer extensions_stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extensions_stuffer, 0));
        EXPECT_SUCCESS(s2n_stuffer_copy(&stuffer, &extensions_stuffer, first_extension_size));

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_extension_recv(&s2n_client_supported_versions_extension, server_conn, &extensions_stuffer));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_stuffer_free(&extensions_stuffer));
    };

    END_TEST();
}
