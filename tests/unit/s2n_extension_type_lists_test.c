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

#include "tls/extensions/s2n_extension_type_lists.h"
#include "tls/s2n_connection.h"

#define LIST_TYPE_SAME_IN_TLS13         S2N_EXTENSION_LIST_CLIENT_HELLO
#define LIST_TYPE_DIFFERENT_IN_TLS13    S2N_EXTENSION_LIST_SERVER_HELLO
#define LIST_TYPE_EMPTY_IN_TLS12        S2N_EXTENSION_LIST_ENCRYPTED_EXTENSIONS

#define EXPECT_NOT_EMPTY_LIST(list) \
        EXPECT_NOT_NULL(list); \
        EXPECT_NOT_EQUAL((list)->count, 0); \
        EXPECT_NOT_NULL((list)->extension_types) \

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_extension_type_list_get */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        const s2n_extension_type_list *list;

        /* Handles nulls */
        EXPECT_FAILURE(s2n_extension_type_list_get(0, conn, NULL));
        EXPECT_SUCCESS(s2n_extension_type_list_get(0, NULL, &list));

        /* Should fail for a bad list type */
        EXPECT_FAILURE(s2n_extension_type_list_get(-1, conn, &list));

        /* Can retrieve the same list for tls1.2 and tls1.3 */
        {
            const s2n_extension_type_list *tls12_list, *tls13_list;

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_SAME_IN_TLS13, conn, &tls12_list));
            EXPECT_NOT_EMPTY_LIST(tls12_list);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_SAME_IN_TLS13, conn, &tls13_list));
            EXPECT_NOT_EMPTY_LIST(tls13_list);

            EXPECT_EQUAL(tls12_list->extension_types, tls13_list->extension_types);
        }

        /* Can retrieve different lists for tls1.2 and tls1.3 */
        {
            const s2n_extension_type_list *tls12_list, *tls13_list;

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_DIFFERENT_IN_TLS13, conn, &tls12_list));
            EXPECT_NOT_EMPTY_LIST(tls12_list);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_DIFFERENT_IN_TLS13, conn, &tls13_list));
            EXPECT_NOT_EMPTY_LIST(tls13_list);

            EXPECT_NOT_EQUAL(tls12_list->extension_types, tls13_list->extension_types);
        }

        /* Retrieves tls1.2 list when protocol version earlier than tls1.2 */
        {
            const s2n_extension_type_list *tls12_list, *tls10_list;
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_DIFFERENT_IN_TLS13, conn, &tls12_list));
            EXPECT_NOT_EMPTY_LIST(tls12_list);

            conn->actual_protocol_version = S2N_TLS10;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_DIFFERENT_IN_TLS13, conn, &tls10_list));
            EXPECT_NOT_EMPTY_LIST(tls10_list);

            EXPECT_EQUAL(tls12_list->extension_types, tls10_list->extension_types);
        }

        /* Retrieves tls1.2 list when protocol version unknown */
        {
            const s2n_extension_type_list *tls12_list, *unknown_version_list;
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_DIFFERENT_IN_TLS13, conn, &tls12_list));
            EXPECT_NOT_EMPTY_LIST(tls12_list);

            conn->actual_protocol_version = S2N_UNKNOWN_PROTOCOL_VERSION;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_DIFFERENT_IN_TLS13, conn, &unknown_version_list));
            EXPECT_NOT_EMPTY_LIST(unknown_version_list);

            EXPECT_EQUAL(tls12_list->extension_types, unknown_version_list->extension_types);
        }

        /* Can retrieve an empty list */
        {
            const s2n_extension_type_list *tls12_list;
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_EMPTY_IN_TLS12, conn, &tls12_list));
            EXPECT_NOT_NULL(tls12_list);
            EXPECT_EQUAL(tls12_list->count, 0);
            EXPECT_NULL(tls12_list->extension_types);
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
}
