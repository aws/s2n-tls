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

#include <stdlib.h>

#include "api/s2n.h"
#include "s2n_test.h"

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    int ctx;

    struct s2n_connection *conn_null = NULL;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

    /* Verify that we can set and get ctx */
    EXPECT_SUCCESS(s2n_connection_set_ctx(conn, &ctx));
    EXPECT_EQUAL(s2n_connection_get_ctx(conn), &ctx);

    /* Verify that conext is cleaned up after wipe */
    EXPECT_SUCCESS(s2n_connection_wipe(conn));
    EXPECT_EQUAL(s2n_connection_get_ctx(conn), NULL);

    EXPECT_SUCCESS(s2n_connection_free(conn));

    /* Verify that we don't assume nonnull input and seg fault */
    EXPECT_NULL(s2n_connection_get_cipher(conn_null));

    END_TEST();
}
