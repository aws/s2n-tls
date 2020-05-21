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
#include "tls/s2n_tls.h"

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
    EXPECT_SUCCESS(s2n_enable_tls13());

    /* Test s2n_extension_type_list_get */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        s2n_extension_type_list *list;

        /* Handles nulls */
        EXPECT_FAILURE(s2n_extension_type_list_get(0, conn, NULL));
        EXPECT_FAILURE(s2n_extension_type_list_get(0, NULL, &list));

        /* Should fail for a bad list type */
        EXPECT_FAILURE(s2n_extension_type_list_get(-1, conn, &list));

        /* Can retrieve the same list for tls1.2 and tls1.3 */
        {
            s2n_extension_type_list *default_list, *tls13_list;

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_SAME_IN_TLS13, conn, &default_list));
            EXPECT_NOT_EMPTY_LIST(default_list);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_SAME_IN_TLS13, conn, &tls13_list));
            EXPECT_NOT_EMPTY_LIST(tls13_list);

            EXPECT_EQUAL(default_list->extension_types, tls13_list->extension_types);
        }

        /* Can retrieve different lists for tls1.2 and tls1.3 */
        {
            s2n_extension_type_list *default_list, *tls13_list;

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_DIFFERENT_IN_TLS13, conn, &default_list));
            EXPECT_NOT_EMPTY_LIST(default_list);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_DIFFERENT_IN_TLS13, conn, &tls13_list));
            EXPECT_NOT_EMPTY_LIST(tls13_list);

            EXPECT_NOT_EQUAL(default_list->extension_types, tls13_list->extension_types);
        }

        /* Retrieves default list when protocol version earlier than tls1.2 */
        {
            s2n_extension_type_list *default_list, *tls10_list;
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_DIFFERENT_IN_TLS13, conn, &default_list));
            EXPECT_NOT_EMPTY_LIST(default_list);

            conn->actual_protocol_version = S2N_TLS10;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_DIFFERENT_IN_TLS13, conn, &tls10_list));
            EXPECT_NOT_EMPTY_LIST(tls10_list);

            EXPECT_EQUAL(default_list->extension_types, tls10_list->extension_types);
        }

        /* Can retrieve an empty list */
        {
            s2n_extension_type_list *empty_list;
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_extension_type_list_get(LIST_TYPE_EMPTY_IN_TLS12, conn, &empty_list));
            EXPECT_NOT_NULL(empty_list);
            EXPECT_EQUAL(empty_list->count, 0);
            EXPECT_NULL(empty_list->extension_types);
        }

        /* Fails to retrieve an invalid list id */
        {
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_FAILURE(s2n_extension_type_list_get(S2N_EXTENSION_LIST_IDS_COUNT, conn, &list));
        }

        /* Can retrieve a list for every id + protocol version */
        {
            for (int i = 0; i < S2N_EXTENSION_LIST_IDS_COUNT; i++) {
                for (int j = 0; j <= s2n_highest_protocol_version; j++) {
                    conn->actual_protocol_version = j;

                    list = NULL;
                    EXPECT_SUCCESS(s2n_extension_type_list_get(i, conn, &list));
                    EXPECT_NOT_NULL(list);
                }
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
}
