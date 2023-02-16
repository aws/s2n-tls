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

#include "crypto/s2n_hmac.h"

#include <string.h>

#include "crypto/s2n_fips.h"
#include "crypto/s2n_hash.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    uint8_t digest_pad[256];
    uint8_t check_pad[256];
    uint8_t output_pad[256];
    struct s2n_stuffer output = { 0 };
    uint8_t sekrit[] = "sekrit";
    uint8_t longsekrit[] = "This is a really really really long key on purpose to make sure that it's longer than the block size";
    uint8_t hello[] = "Hello world!";
    uint8_t string1[] = "String 1";
    uint8_t string2[] = "and String 2";
    struct s2n_hmac_state hmac, copy, cmac;

    struct s2n_blob out = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&out, output_pad, sizeof(output_pad)));

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    EXPECT_SUCCESS(s2n_hmac_new(&hmac));
    EXPECT_SUCCESS(s2n_hmac_new(&copy));
    EXPECT_SUCCESS(s2n_hmac_new(&cmac));

    if (s2n_hmac_is_available(S2N_HMAC_SSLv3_MD5)) {
        /* Try SSLv3 MD5 */
        uint8_t hmac_sslv3_md5_size;
        POSIX_GUARD(s2n_hmac_digest_size(S2N_HMAC_SSLv3_MD5, &hmac_sslv3_md5_size));
        EXPECT_EQUAL(hmac_sslv3_md5_size, 16);
        EXPECT_SUCCESS(s2n_hmac_init(&hmac, S2N_HMAC_SSLv3_MD5, sekrit, strlen((char *) sekrit)));
        EXPECT_SUCCESS(s2n_hmac_update(&hmac, hello, strlen((char *) hello)));
        EXPECT_SUCCESS(s2n_hmac_digest(&hmac, digest_pad, 16));

        EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
        for (int i = 0; i < 16; i++) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
        }

        /* Reference value from Go */
        EXPECT_EQUAL(memcmp(output_pad, "d4f0d06b9765de23e6c3e33a24c5ded0", 16 * 2), 0);

        /* Test that a reset works */
        EXPECT_SUCCESS(s2n_hmac_reset(&hmac));
        EXPECT_SUCCESS(s2n_hmac_update(&hmac, hello, strlen((char *) hello)));
        EXPECT_SUCCESS(s2n_hmac_digest(&hmac, digest_pad, 16));

        EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
        for (int i = 0; i < 16; i++) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
        }

        /* Reference value from Go */
        EXPECT_EQUAL(memcmp(output_pad, "d4f0d06b9765de23e6c3e33a24c5ded0", 16 * 2), 0);

        EXPECT_SUCCESS(s2n_hmac_reset(&hmac));
    }

    if (s2n_hmac_is_available(S2N_HMAC_SSLv3_SHA1)) {
        /* Try SSLv3 SHA1 */
        uint8_t hmac_sslv3_sha1_size;
        POSIX_GUARD(s2n_hmac_digest_size(S2N_HMAC_SSLv3_SHA1, &hmac_sslv3_sha1_size));
        EXPECT_EQUAL(hmac_sslv3_sha1_size, 20);
        EXPECT_SUCCESS(s2n_hmac_init(&hmac, S2N_HMAC_SSLv3_SHA1, sekrit, strlen((char *) sekrit)));
        EXPECT_SUCCESS(s2n_hmac_update(&hmac, hello, strlen((char *) hello)));
        EXPECT_SUCCESS(s2n_hmac_digest(&hmac, digest_pad, 20));

        EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
        for (int i = 0; i < 20; i++) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
        }

        /* Reference value from Go */
        EXPECT_EQUAL(memcmp(output_pad, "b0c66179f6eb5a46b4b7c4fca84b3ea5161b7326", 20 * 2), 0);

        /* Test that a reset works */
        EXPECT_SUCCESS(s2n_hmac_reset(&hmac));
        EXPECT_SUCCESS(s2n_hmac_update(&hmac, hello, strlen((char *) hello)));
        EXPECT_SUCCESS(s2n_hmac_digest(&hmac, digest_pad, 20));

        EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
        for (int i = 0; i < 20; i++) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
        }

        /* Reference value from Go */
        EXPECT_EQUAL(memcmp(output_pad, "b0c66179f6eb5a46b4b7c4fca84b3ea5161b7326", 20 * 2), 0);

        EXPECT_SUCCESS(s2n_hmac_reset(&hmac));
    }

    if (s2n_hmac_is_available(S2N_HMAC_MD5)) {
        /* Try MD5 */
        uint8_t hmac_md5_size;
        POSIX_GUARD(s2n_hmac_digest_size(S2N_HMAC_MD5, &hmac_md5_size));
        EXPECT_EQUAL(hmac_md5_size, 16);
        EXPECT_SUCCESS(s2n_hmac_init(&hmac, S2N_HMAC_MD5, sekrit, strlen((char *) sekrit)));
        EXPECT_SUCCESS(s2n_hmac_update(&hmac, hello, strlen((char *) hello)));
        EXPECT_SUCCESS(s2n_hmac_digest(&hmac, digest_pad, 16));

        EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
        for (int i = 0; i < 16; i++) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
        }

        /* Reference value from python */
        EXPECT_EQUAL(memcmp(output_pad, "3ad68c53dc1a3cf35f6469877fae4585", 16 * 2), 0);

        EXPECT_SUCCESS(s2n_hmac_reset(&hmac));
    }

    /* Try SHA1 */
    uint8_t hmac_sha1_size;
    POSIX_GUARD(s2n_hmac_digest_size(S2N_HMAC_SHA1, &hmac_sha1_size));
    EXPECT_EQUAL(hmac_sha1_size, 20);
    EXPECT_SUCCESS(s2n_hmac_init(&hmac, S2N_HMAC_SHA1, sekrit, strlen((char *) sekrit)));
    EXPECT_SUCCESS(s2n_hmac_update(&hmac, hello, strlen((char *) hello)));
    EXPECT_SUCCESS(s2n_hmac_copy(&copy, &hmac));
    EXPECT_SUCCESS(s2n_hmac_digest(&hmac, digest_pad, 20));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 20; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from python */
    EXPECT_EQUAL(memcmp(output_pad, "6d301861b599938eca94f6de917362886d97882f", 20 * 2), 0);

    /* Check the copy */
    EXPECT_SUCCESS(s2n_hmac_digest(&copy, digest_pad, 20));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 20; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from python */
    EXPECT_EQUAL(memcmp(output_pad, "6d301861b599938eca94f6de917362886d97882f", 20 * 2), 0);

    /* Test that a reset works, and test that a multi-update works */
    EXPECT_SUCCESS(s2n_hmac_reset(&hmac));
    EXPECT_SUCCESS(s2n_hmac_reset(&copy));
    EXPECT_SUCCESS(s2n_hmac_update(&hmac, string1, strlen((char *) string1)));
    EXPECT_SUCCESS(s2n_hmac_copy(&copy, &hmac));
    EXPECT_SUCCESS(s2n_hmac_update(&hmac, string2, strlen((char *) string2)));
    EXPECT_SUCCESS(s2n_hmac_digest(&hmac, digest_pad, 20));
    EXPECT_SUCCESS(s2n_hmac_free(&hmac));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 20; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from python */
    EXPECT_EQUAL(memcmp(output_pad, "6144020409573b75a7093c1ec16c0c43030769aa", 20 * 2), 0);

    /* Test that a copy-update works */
    EXPECT_SUCCESS(s2n_hmac_update(&copy, string2, strlen((char *) string2)));
    EXPECT_SUCCESS(s2n_hmac_digest(&copy, digest_pad, 20));
    EXPECT_SUCCESS(s2n_hmac_free(&copy));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 20; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from python */
    EXPECT_EQUAL(memcmp(output_pad, "6144020409573b75a7093c1ec16c0c43030769aa", 20 * 2), 0);

    /* Test that a long secret works */
    EXPECT_SUCCESS(s2n_hmac_new(&hmac));
    EXPECT_SUCCESS(s2n_hmac_init(&hmac, S2N_HMAC_SHA1, longsekrit, strlen((char *) longsekrit)));
    EXPECT_SUCCESS(s2n_hmac_update(&hmac, hello, strlen((char *) hello)));
    EXPECT_SUCCESS(s2n_hmac_digest(&hmac, digest_pad, 20));
    EXPECT_SUCCESS(s2n_hmac_free(&hmac));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 20; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from python */
    EXPECT_EQUAL(memcmp(output_pad, "9c0e7b5a2f0efe770db4640a6f30c76d2b9c0fee", 20 * 2), 0);

    /* Verify that _verify works */
    EXPECT_SUCCESS(s2n_hmac_init(&cmac, S2N_HMAC_SHA1, longsekrit, strlen((char *) longsekrit)));
    EXPECT_SUCCESS(s2n_hmac_update(&cmac, hello, strlen((char *) hello)));
    EXPECT_SUCCESS(s2n_hmac_digest(&cmac, check_pad, 20));
    EXPECT_SUCCESS(s2n_hmac_digest_verify(digest_pad, check_pad, 20));
    EXPECT_SUCCESS(s2n_hmac_free(&cmac));

    /* Try SHA224 */
    EXPECT_SUCCESS(s2n_hmac_new(&hmac));

    uint8_t hmac_sha224_size;
    POSIX_GUARD(s2n_hmac_digest_size(S2N_HMAC_SHA224, &hmac_sha224_size));
    EXPECT_EQUAL(hmac_sha224_size, 28);
    EXPECT_SUCCESS(s2n_hmac_init(&hmac, S2N_HMAC_SHA224, sekrit, strlen((char *) sekrit)));
    EXPECT_SUCCESS(s2n_hmac_update(&hmac, hello, strlen((char *) hello)));
    EXPECT_SUCCESS(s2n_hmac_digest(&hmac, digest_pad, 28));
    EXPECT_SUCCESS(s2n_hmac_free(&hmac));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 28; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from python */
    EXPECT_EQUAL(memcmp(output_pad, "095f9b54295575c9ac5352b1c366dd6adb2bb1133b6587e4990f33b4", 28 * 2), 0);

    /* Try SHA256 */
    EXPECT_SUCCESS(s2n_hmac_new(&hmac));

    uint8_t hmac_sha256_size;
    POSIX_GUARD(s2n_hmac_digest_size(S2N_HMAC_SHA256, &hmac_sha256_size));
    EXPECT_EQUAL(hmac_sha256_size, 32);
    EXPECT_SUCCESS(s2n_hmac_init(&hmac, S2N_HMAC_SHA256, sekrit, strlen((char *) sekrit)));
    EXPECT_SUCCESS(s2n_hmac_update(&hmac, hello, strlen((char *) hello)));
    EXPECT_SUCCESS(s2n_hmac_digest(&hmac, digest_pad, 32));
    EXPECT_SUCCESS(s2n_hmac_free(&hmac));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 32; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from python */
    EXPECT_EQUAL(memcmp(output_pad, "adc20b12d236e6d1824d690622e33ead4f67ba5a2be9606fe762b2dd859a78a9", 32 * 2), 0);

    /* Try SHA384 */
    EXPECT_SUCCESS(s2n_hmac_new(&hmac));

    uint8_t hmac_sha384_size;
    POSIX_GUARD(s2n_hmac_digest_size(S2N_HMAC_SHA384, &hmac_sha384_size));
    EXPECT_EQUAL(hmac_sha384_size, 48);
    EXPECT_SUCCESS(s2n_hmac_init(&hmac, S2N_HMAC_SHA384, sekrit, strlen((char *) sekrit)));
    EXPECT_SUCCESS(s2n_hmac_update(&hmac, hello, strlen((char *) hello)));
    EXPECT_SUCCESS(s2n_hmac_digest(&hmac, digest_pad, 48));
    EXPECT_SUCCESS(s2n_hmac_free(&hmac));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 48; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from python */
    EXPECT_EQUAL(memcmp(output_pad, "8552563cadd583b79dcc7225bb79bc6483c63f259187162e1c9d4283eb6299ef1bc3ca81c0c40fc7b22f7a1f3b93adb4", 48 * 2), 0);

    /* Try SHA512 */
    EXPECT_SUCCESS(s2n_hmac_new(&hmac));

    uint8_t hmac_sha512_size;
    POSIX_GUARD(s2n_hmac_digest_size(S2N_HMAC_SHA512, &hmac_sha512_size));
    EXPECT_EQUAL(hmac_sha512_size, 64);
    EXPECT_SUCCESS(s2n_hmac_init(&hmac, S2N_HMAC_SHA512, sekrit, strlen((char *) sekrit)));
    EXPECT_SUCCESS(s2n_hmac_update(&hmac, hello, strlen((char *) hello)));
    EXPECT_SUCCESS(s2n_hmac_digest(&hmac, digest_pad, 64));
    EXPECT_SUCCESS(s2n_hmac_free(&hmac));

    EXPECT_SUCCESS(s2n_stuffer_init(&output, &out));
    for (int i = 0; i < 64; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&output, digest_pad[i]));
    }

    /* Reference value from python */
    EXPECT_EQUAL(memcmp(output_pad, "0a834a1ed265042e2897405edb4fdd9818950cd5bea10b828f2fed45a1cb6dbd2107e4b04eb20f211998cd4e8c7e11ebdcb0103ac63882481e1bb8083d07f4be", 64 * 2), 0);

    END_TEST();
}
