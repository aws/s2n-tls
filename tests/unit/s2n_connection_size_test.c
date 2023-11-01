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
#include "tls/s2n_connection.h"

bool is_32_bit_platform()
{
    return (sizeof(void *) == 4);
}

/* Test s2n_connection does not grow too much.
 * s2n_connection is a very large structure. We should be working to reduce its
 * size, not increasing it.
 * This test documents changes to its size for reviewers so that we can
 * make very deliberate choices about increasing memory usage.
 *
 * We can't easily enforce an exact size for s2n_connection because it varies
 * based on some settings (like how many KEM groups are supported).
 */
int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* We don't run this test on 32 bit platforms. The goal of this test is
     * accomplished as long as it is running on any platform in our CI, and
     * just running it on a single platform keeps us from having to maintain
     * multiple static constants.
    */
    if (is_32_bit_platform()) {
        END_TEST();
        return 0;
    }

    /* Carefully consider any increases to this number. */
    const uint16_t max_connection_size = 4274;
    const uint16_t min_connection_size = max_connection_size * 0.9;

    size_t connection_size = sizeof(struct s2n_connection);

    if (connection_size > max_connection_size || connection_size < min_connection_size) {
        const char message[] = "s2n_connection size (%zu) no longer in (%i, %i). "
                               "Please verify that this change was intentional and then update this test.";
        char message_buffer[sizeof(message) + 100] = { 0 };
        int r = snprintf(message_buffer, sizeof(message_buffer), message,
                connection_size, min_connection_size, max_connection_size);
        EXPECT_TRUE(r < sizeof(message_buffer));
        FAIL_MSG(message_buffer);
    }

    END_TEST();
}
