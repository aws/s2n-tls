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

#include "tls/extensions/s2n_extension_type_lists.h"

#include "s2n_test.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    /* Test s2n_extension_type_list_get */
    {
        s2n_extension_type_list *list = NULL;

        /* Safety checks */
        {
            EXPECT_FAILURE(s2n_extension_type_list_get(0, NULL));

            /* Should fail for a bad list type */
            EXPECT_FAILURE(s2n_extension_type_list_get(-1, &list));
            EXPECT_FAILURE(s2n_extension_type_list_get(S2N_EXTENSION_LIST_IDS_COUNT, &list));
        };

        /* Can retrieve a list for every id */
        {
            for (size_t i = 0; i < S2N_EXTENSION_LIST_IDS_COUNT; i++) {
                list = NULL;
                EXPECT_SUCCESS(s2n_extension_type_list_get(i, &list));
                EXPECT_NOT_NULL(list);
            }
        };
    };

    END_TEST();
}
