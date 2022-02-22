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
#include "tls/s2n_internal.h"

#include "tls/s2n_connection.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_internal_connection_get_config */
    {
        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NULL(s2n_internal_connection_get_config(conn));

        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_NOT_NULL(s2n_internal_connection_get_config(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    END_TEST();
}
