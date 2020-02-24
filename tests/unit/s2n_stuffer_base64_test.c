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
#include <string.h>
#include <s2n.h>

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_random.h"

int main(int argc, char **argv)
{
    char hello_world[] = "Hello world!";
    uint8_t hello_world_base64[] = "SGVsbG8gd29ybGQhAA==";
    struct s2n_stuffer stuffer, known_data, scratch, entropy, mirror;
    uint8_t pad[50];
    struct s2n_blob r = {.data = pad, .size = sizeof(pad)};

    BEGIN_TEST();
    

    /* Create a 100 byte stuffer */
    EXPECT_SUCCESS(s2n_stuffer_alloc(&stuffer, 1000));

    /* Write our known data */
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_string(&known_data, hello_world));
    EXPECT_SUCCESS(s2n_stuffer_write_base64(&stuffer, &known_data));
    EXPECT_SUCCESS(s2n_stuffer_free(&known_data));

    /* Check it against the known output */
    EXPECT_EQUAL(memcmp(stuffer.blob.data, hello_world_base64, strlen((char *)hello_world)), 0);

    /* Check that we can read it again */
    EXPECT_SUCCESS(s2n_stuffer_alloc(&scratch, 50));
    EXPECT_SUCCESS(s2n_stuffer_read_base64(&stuffer, &scratch));
    EXPECT_SUCCESS(memcmp(scratch.blob.data, hello_world, strlen(hello_world)));

    /* Now try with some randomly generated data. Make sure we try each boundary case,
     * where size % 3 == 0, 1, 2
     */
    EXPECT_SUCCESS(s2n_stuffer_alloc(&entropy, 50));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&mirror, 50));

    for (int i = entropy.blob.size; i > 0; i--) {
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&entropy));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&mirror));

        /* Get i bytes of random data */
        r.size = i;
        EXPECT_SUCCESS(s2n_get_urandom_data(&r));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&entropy, pad, i));

        /* Write i bytes  it, base64 encoded */
        /* Read it back, decoded */
        EXPECT_SUCCESS(s2n_stuffer_write_base64(&stuffer, &entropy));

        /* Should be (i / 3) * 4 + a carry  */
        EXPECT_EQUAL((i / 3) * 4 + ((i % 3) ? 4 : 0), s2n_stuffer_data_available(&stuffer));

        /* Read it back, decoded */
        EXPECT_SUCCESS(s2n_stuffer_read_base64(&stuffer, &mirror));

        /* Verify it's the same */
        EXPECT_EQUAL(memcmp(mirror.blob.data, entropy.blob.data, i), 0);
    }

    EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    EXPECT_SUCCESS(s2n_stuffer_free(&scratch));
    EXPECT_SUCCESS(s2n_stuffer_free(&mirror));
    EXPECT_SUCCESS(s2n_stuffer_free(&entropy));

    END_TEST();
}
