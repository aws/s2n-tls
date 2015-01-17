/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <string.h>

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    uint8_t wire[2];
    int count;

    BEGIN_TEST();

    EXPECT_SUCCESS(setenv("S2N_ENABLE_INSECURE_CLIENT", "1", 0));
    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

    count = 0;
    for (int i = 0; i < 0xffff; i++) {
        wire[0] = (i >> 8);
        wire[1] = i & 0xff;

        if (s2n_set_cipher_as_client(conn, wire) == 0) {
            count++;
        }
    }

    /* We should have exactly 12 cipher suites */
    EXPECT_EQUAL(count, 12);

    END_TEST();
}
