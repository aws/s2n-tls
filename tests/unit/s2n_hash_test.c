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

#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_hash.h"
#include "utils/s2n_blob.h"

int main(int argc, char **argv)
{
    uint8_t digest_pad[64];
    uint8_t output_pad[96];
    uint8_t hello[] = "Hello world!\n";
    struct s2n_stuffer output;
    struct s2n_hash_state hash, copy;
    struct s2n_blob out = {.data = output_pad,.size = sizeof(output_pad) };

    BEGIN_TEST();

    /* Initialise our output stuffers */
    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));

    EXPECT_EQUAL(s2n_hash_digest_size(S2N_HASH_MD5), 16);
    EXPECT_SUCCESS(s2n_hash_init(&hash, S2N_HASH_MD5));
    EXPECT_SUCCESS(s2n_hash_update(&hash, hello, strlen((char *)hello)));
    EXPECT_SUCCESS(s2n_hash_copy(&copy, &hash));
    EXPECT_SUCCESS(s2n_hash_digest(&hash, digest_pad, MD5_DIGEST_LENGTH));

    for (int i = 0; i < 16; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from command line md5sum */
    EXPECT_EQUAL(memcmp(output_pad, "59ca0efa9f5633cb0371bbc0355478d8", 16 * 2), 0);

    /* Check the copy */
    EXPECT_SUCCESS(s2n_hash_digest(&copy, digest_pad, MD5_DIGEST_LENGTH));

    for (int i = 0; i < 16; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from command line md5sum */
    EXPECT_EQUAL(memcmp(output_pad, "59ca0efa9f5633cb0371bbc0355478d8", 16 * 2), 0);

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    EXPECT_EQUAL(s2n_hash_digest_size(S2N_HASH_SHA1), 20);
    EXPECT_SUCCESS(s2n_hash_init(&hash, S2N_HASH_SHA1));
    EXPECT_SUCCESS(s2n_hash_update(&hash, hello, strlen((char *)hello)));
    EXPECT_SUCCESS(s2n_hash_digest(&hash, digest_pad, SHA_DIGEST_LENGTH));

    for (int i = 0; i < 20; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from command line sha1sum */
    EXPECT_EQUAL(memcmp(output_pad, "47a013e660d408619d894b20806b1d5086aab03b", 20 * 2), 0);

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    EXPECT_EQUAL(s2n_hash_digest_size(S2N_HASH_SHA256), 32);
    EXPECT_SUCCESS(s2n_hash_init(&hash, S2N_HASH_SHA256));
    EXPECT_SUCCESS(s2n_hash_update(&hash, hello, strlen((char *)hello)));
    EXPECT_SUCCESS(s2n_hash_digest(&hash, digest_pad, SHA256_DIGEST_LENGTH));

    for (int i = 0; i < 32; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from command line sha256sum */
    EXPECT_EQUAL(memcmp(output_pad, "0ba904eae8773b70c75333db4de2f3ac45a8ad4ddba1b242f0b3cfc199391dd8", 32 * 2), 0);

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    EXPECT_EQUAL(s2n_hash_digest_size(S2N_HASH_SHA384), 48);
    EXPECT_SUCCESS(s2n_hash_init(&hash, S2N_HASH_SHA384));
    EXPECT_SUCCESS(s2n_hash_update(&hash, hello, strlen((char *)hello)));
    EXPECT_SUCCESS(s2n_hash_digest(&hash, digest_pad, SHA384_DIGEST_LENGTH));

    for (int i = 0; i < 48; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from command line sha512sum */
    EXPECT_EQUAL(memcmp(output_pad, "f7f8f1b9d5a9a61742eeda26c20990282ac08dabda14e70376fcb4c8b46198a9959ea9d7d194b38520eed5397ffe6d8e", 48 * 2), 0);

    END_TEST();
}
