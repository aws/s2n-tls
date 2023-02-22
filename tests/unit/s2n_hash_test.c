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

#include "crypto/s2n_hash.h"

#include <string.h>

#include "crypto/s2n_fips.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    uint8_t digest_pad[64];
    uint8_t output_pad[128];
    uint8_t hello[] = "Hello world!\n";
    uint8_t string1[] = "String 1\n";
    uint8_t string2[] = "and String 2\n";
    struct s2n_stuffer output = { 0 };
    struct s2n_hash_state hash, copy;
    struct s2n_blob out = { 0 };
    POSIX_GUARD(s2n_blob_init(&out, output_pad, sizeof(output_pad)));
    uint64_t bytes_in_hash;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Sanity check that we're setting S2N_LIBCRYPTO_SUPPORTS_EVP_MD5_SHA1_HASH properly.
     * AWS-LC is known to support EVP_md5_sha1(). If this fails, something is wrong with our
     * S2N_LIBCRYPTO_SUPPORTS_EVP_MD5_SHA1_HASH feature testing.
     */
    if (s2n_libcrypto_is_awslc()) {
        EXPECT_NOT_NULL(s2n_hash_alg_to_evp_md(S2N_HASH_MD5_SHA1));
    }

    POSIX_GUARD(s2n_hash_new(&hash));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    POSIX_GUARD(s2n_hash_new(&copy));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&copy));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&copy, &bytes_in_hash));

    if (s2n_hash_is_available(S2N_HASH_MD5)) {
        /* Try MD5 */
        uint8_t md5_digest_size;
        POSIX_GUARD(s2n_hash_digest_size(S2N_HASH_MD5, &md5_digest_size));
        EXPECT_EQUAL(md5_digest_size, 16);
        EXPECT_SUCCESS(s2n_hash_init(&hash, S2N_HASH_MD5));
        EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
        EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
        EXPECT_EQUAL(bytes_in_hash, 0);

        EXPECT_SUCCESS(s2n_hash_update(&hash, hello, strlen((char *) hello)));
        EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
        EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
        EXPECT_EQUAL(bytes_in_hash, 13);

        EXPECT_SUCCESS(s2n_hash_digest(&hash, digest_pad, MD5_DIGEST_LENGTH));
        EXPECT_FALSE(s2n_hash_is_ready_for_input(&hash));
        EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));

        EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
        for (int i = 0; i < 16; i++) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
        }

        /* Reference value from command line md5sum */
        EXPECT_EQUAL(memcmp(output_pad, "59ca0efa9f5633cb0371bbc0355478d8", 16 * 2), 0);

        POSIX_GUARD(s2n_hash_reset(&hash));
        EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
        EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
        EXPECT_EQUAL(bytes_in_hash, 0);
    }

    /* Try SHA1 */
    uint8_t sha1_digest_size;
    POSIX_GUARD(s2n_hash_digest_size(S2N_HASH_SHA1, &sha1_digest_size));
    EXPECT_EQUAL(sha1_digest_size, 20);
    EXPECT_SUCCESS(s2n_hash_init(&hash, S2N_HASH_SHA1));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 0);

    EXPECT_SUCCESS(s2n_hash_update(&hash, hello, strlen((char *) hello)));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 13);

    EXPECT_SUCCESS(s2n_hash_copy(&copy, &hash));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&copy));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&copy, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 13);

    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 13);

    EXPECT_SUCCESS(s2n_hash_digest(&hash, digest_pad, SHA_DIGEST_LENGTH));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 20; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from command line sha1sum */
    EXPECT_EQUAL(memcmp(output_pad, "47a013e660d408619d894b20806b1d5086aab03b", 20 * 2), 0);

    /* Check the copy */
    EXPECT_SUCCESS(s2n_hash_digest(&copy, digest_pad, SHA_DIGEST_LENGTH));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&copy));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&copy, &bytes_in_hash));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 20; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from command line sha1sum */
    EXPECT_EQUAL(memcmp(output_pad, "47a013e660d408619d894b20806b1d5086aab03b", 20 * 2), 0);

    EXPECT_SUCCESS(s2n_hash_reset(&hash));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 0);

    EXPECT_SUCCESS(s2n_hash_reset(&copy));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&copy));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&copy, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 0);

    /* Test that a multi-update works */
    EXPECT_SUCCESS(s2n_hash_update(&hash, string1, strlen((char *) string1)));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 9);

    EXPECT_SUCCESS(s2n_hash_copy(&copy, &hash));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&copy));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&copy, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 9);

    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 9);

    EXPECT_SUCCESS(s2n_hash_update(&hash, string2, strlen((char *) string2)));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 22);

    EXPECT_SUCCESS(s2n_hash_digest(&hash, digest_pad, SHA_DIGEST_LENGTH));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 20; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from command line sha1sum */
    EXPECT_EQUAL(memcmp(output_pad, "4afd618f797f0c6bd85b2035338bb26c62ab0dbc", 20 * 2), 0);

    /* Test that a copy-update works */
    EXPECT_SUCCESS(s2n_hash_update(&copy, string2, strlen((char *) string2)));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&copy));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&copy, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 22);

    EXPECT_SUCCESS(s2n_hash_digest(&copy, digest_pad, SHA_DIGEST_LENGTH));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&copy));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&copy, &bytes_in_hash));

    EXPECT_SUCCESS(s2n_hash_free(&copy));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&copy));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&copy, &bytes_in_hash));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 20; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from command line sha1sum */
    EXPECT_EQUAL(memcmp(output_pad, "4afd618f797f0c6bd85b2035338bb26c62ab0dbc", 20 * 2), 0);

    POSIX_GUARD(s2n_hash_reset(&hash));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 0);

    /* Try SHA224 and test s2n_hash_free */
    uint8_t sha224_digest_size;
    POSIX_GUARD(s2n_hash_digest_size(S2N_HASH_SHA224, &sha224_digest_size));
    EXPECT_EQUAL(sha224_digest_size, 28);
    EXPECT_SUCCESS(s2n_hash_init(&hash, S2N_HASH_SHA224));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 0);

    EXPECT_SUCCESS(s2n_hash_update(&hash, hello, strlen((char *) hello)));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 13);

    EXPECT_SUCCESS(s2n_hash_digest(&hash, digest_pad, SHA224_DIGEST_LENGTH));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));

    EXPECT_SUCCESS(s2n_hash_free(&hash));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 28; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from command line sha224sum */
    EXPECT_EQUAL(memcmp(output_pad, "f771a839cff678857feee21492184ca7a456ac3cf57e78057b7beaf5", 28 * 2), 0);

    /* Try SHA256 using a freed hash state */
    POSIX_GUARD(s2n_hash_new(&hash));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));

    uint8_t sha256_digest_size;
    POSIX_GUARD(s2n_hash_digest_size(S2N_HASH_SHA256, &sha256_digest_size));
    EXPECT_EQUAL(sha256_digest_size, 32);
    EXPECT_SUCCESS(s2n_hash_init(&hash, S2N_HASH_SHA256));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 0);

    EXPECT_SUCCESS(s2n_hash_update(&hash, hello, strlen((char *) hello)));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 13);

    EXPECT_SUCCESS(s2n_hash_digest(&hash, digest_pad, SHA256_DIGEST_LENGTH));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 32; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from command line sha256sum */
    EXPECT_EQUAL(memcmp(output_pad, "0ba904eae8773b70c75333db4de2f3ac45a8ad4ddba1b242f0b3cfc199391dd8", 32 * 2), 0);

    POSIX_GUARD(s2n_hash_reset(&hash));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 0);

    /* Try SHA384 */
    uint8_t sha384_digest_size;
    POSIX_GUARD(s2n_hash_digest_size(S2N_HASH_SHA384, &sha384_digest_size));
    EXPECT_EQUAL(sha384_digest_size, 48);
    EXPECT_SUCCESS(s2n_hash_init(&hash, S2N_HASH_SHA384));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 0);

    EXPECT_SUCCESS(s2n_hash_update(&hash, hello, strlen((char *) hello)));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 13);

    EXPECT_SUCCESS(s2n_hash_digest(&hash, digest_pad, SHA384_DIGEST_LENGTH));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 48; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from command line sha384sum */
    EXPECT_EQUAL(memcmp(output_pad, "f7f8f1b9d5a9a61742eeda26c20990282ac08dabda14e70376fcb4c8b46198a9959ea9d7d194b38520eed5397ffe6d8e", 48 * 2), 0);

    POSIX_GUARD(s2n_hash_reset(&hash));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 0);

    /* Try SHA512 */
    uint8_t sha512_digest_size;
    POSIX_GUARD(s2n_hash_digest_size(S2N_HASH_SHA512, &sha512_digest_size));
    EXPECT_EQUAL(sha512_digest_size, 64);
    EXPECT_SUCCESS(s2n_hash_init(&hash, S2N_HASH_SHA512));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 0);

    EXPECT_SUCCESS(s2n_hash_update(&hash, hello, strlen((char *) hello)));
    EXPECT_TRUE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));
    EXPECT_EQUAL(bytes_in_hash, 13);

    EXPECT_SUCCESS(s2n_hash_digest(&hash, digest_pad, SHA512_DIGEST_LENGTH));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));

    EXPECT_SUCCESS(s2n_hash_free(&hash));
    EXPECT_FALSE(s2n_hash_is_ready_for_input(&hash));
    EXPECT_FAILURE(s2n_hash_get_currently_in_hash_total(&hash, &bytes_in_hash));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 64; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from command line sha512sum */
    EXPECT_EQUAL(memcmp(output_pad, "32c07a0b3a3fd0dd8f28021b4eea1c19d871f4586316b394124f3c99fb68e59579e05039c3bd9aab9841214f1c132f7666eb8800f14be8b9b091a7dba32bfe6f", 64 * 2), 0);

    END_TEST();
}
