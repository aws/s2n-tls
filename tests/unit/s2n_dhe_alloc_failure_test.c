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

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "crypto/s2n_dhe.h"
#include "crypto/s2n_openssl.h"
#include "s2n_test.h"

/* The custom libcrypto allocator signature below matches OpenSSL 1.1.0+ and AWS-LC */
#if S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 0) && !defined(OPENSSL_IS_BORINGSSL) && !defined(LIBRESSL_VERSION_NUMBER)
    #define S2N_TEST_LIBCRYPTO_MEM_HOOKS 1
#endif

#ifdef S2N_TEST_LIBCRYPTO_MEM_HOOKS
static int64_t live_allocations = 0;
static uint32_t allocation_count = 0;
static uint32_t fail_allocation = 0;

static void *test_malloc(size_t size, const char *file, int line)
{
    (void) file;
    (void) line;
    if (++allocation_count == fail_allocation) {
        return NULL;
    }
    void *ptr = malloc(size);
    if (ptr) {
        live_allocations++;
    }
    return ptr;
}

static void *test_realloc(void *ptr, size_t size, const char *file, int line)
{
    if (ptr == NULL) {
        return test_malloc(size, file, line);
    }
    if (++allocation_count == fail_allocation) {
        return NULL;
    }
    return realloc(ptr, size);
}

static void test_free(void *ptr, const char *file, int line)
{
    (void) file;
    (void) line;
    if (ptr) {
        live_allocations--;
    }
    free(ptr);
}
#endif

int main(int argc, char **argv)
{
    BEGIN_TEST_NO_INIT();

#ifdef S2N_TEST_LIBCRYPTO_MEM_HOOKS
    /* The hooks must be installed before libcrypto allocates anything, so before s2n_init */
    bool hooks_installed = CRYPTO_set_mem_functions(test_malloc, test_realloc, test_free);
#endif

    EXPECT_SUCCESS(s2n_init());

#ifdef S2N_TEST_LIBCRYPTO_MEM_HOOKS
    /* s2n_dh_p_g_Ys_to_dh_params must not leak when any libcrypto allocation fails */
    if (hooks_installed) {
        /* 2048-bit p: the values only need to parse into BIGNUMs and pass the DH checks */
        uint8_t p_data[256] = { 0 };
        memset(p_data, 0xff, sizeof(p_data));
        uint8_t g_data[] = { 2 };
        uint8_t ys_data[] = { 3 };

        struct s2n_blob p = { 0 }, g = { 0 }, ys = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&p, p_data, sizeof(p_data)));
        EXPECT_SUCCESS(s2n_blob_init(&g, g_data, sizeof(g_data)));
        EXPECT_SUCCESS(s2n_blob_init(&ys, ys_data, sizeof(ys_data)));

        /* Fail each allocation in turn until the call no longer hits a failure */
        bool succeeded = false;
        for (uint32_t i = 1; i < 100 && !succeeded; i++) {
            int64_t live_before = live_allocations;
            allocation_count = 0;
            fail_allocation = i;

            struct s2n_dh_params params = { 0 };
            succeeded = (s2n_dh_p_g_Ys_to_dh_params(&params, &p, &g, &ys) == S2N_SUCCESS);
            fail_allocation = 0;
            EXPECT_SUCCESS(s2n_dh_params_free(&params));

            /* OpenSSL 3 keeps allocations for queued errors until the queue is cleared */
            ERR_clear_error();
            EXPECT_EQUAL(live_allocations, live_before);
        }
        EXPECT_TRUE(succeeded);
    }
#endif

    END_TEST();
}
