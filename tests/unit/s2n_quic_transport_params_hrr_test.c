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

/*
 * Test that calling s2n_quic_transport_params_recv twice on the same
 * connection (as happens during a HelloRetryRequest) does not leak
 * the first allocation.
 *
 * Uses custom memory callbacks to track every malloc/free and detect
 * orphaned allocations.
 */

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_quic_transport_params.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_quic_support.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_mem.h"

#define MAX_TRACKED_ALLOCS 4096

static struct {
    void *ptr;
    uint32_t size;
    bool active;
} s_alloc_table[MAX_TRACKED_ALLOCS];

/* Saved original callbacks so we can delegate the actual malloc/free */
static s2n_mem_malloc_callback s_real_malloc = NULL;
static s2n_mem_free_callback s_real_free = NULL;
static size_t s_count_active_allocs(void)
{
    size_t count = 0;
    for (size_t i = 0; i < MAX_TRACKED_ALLOCS; i++) {
        if (s_alloc_table[i].active) {
            count++;
        }
    }
    return count;
}

static int s_tracking_malloc(void **ptr, uint32_t requested, uint32_t *allocated)
{
    int rc = s_real_malloc(ptr, requested, allocated);
    if (rc == S2N_SUCCESS && *ptr != NULL) {
        for (size_t i = 0; i < MAX_TRACKED_ALLOCS; i++) {
            if (!s_alloc_table[i].active) {
                s_alloc_table[i].ptr = *ptr;
                s_alloc_table[i].size = *allocated;
                s_alloc_table[i].active = true;
                break;
            }
        }
    }
    return rc;
}

static int s_tracking_free(void *ptr, uint32_t size)
{
    if (ptr != NULL) {
        for (size_t i = 0; i < MAX_TRACKED_ALLOCS; i++) {
            if (s_alloc_table[i].active && s_alloc_table[i].ptr == ptr) {
                s_alloc_table[i].active = false;
                break;
            }
        }
    }
    return s_real_free(ptr, size);
}

static const uint8_t FIRST_PARAMS[] = "first transport parameters payload";
static const uint8_t SECOND_PARAMS[] = "second (different size) transport parameters";

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    /* Save the real memory callbacks and install tracking wrappers.
     * We track all allocations from the start so the test flow is
     * simply: do all the things, free all the things, assert zero. */
    {
        s2n_mem_init_callback mem_init_cb = NULL;
        s2n_mem_cleanup_callback mem_cleanup_cb = NULL;
        EXPECT_OK(s2n_mem_get_callbacks(&mem_init_cb, &mem_cleanup_cb,
                &s_real_malloc, &s_real_free));
        EXPECT_OK(s2n_mem_override_callbacks(mem_init_cb, mem_cleanup_cb,
                s_tracking_malloc, s_tracking_free));
    }

    /* Test: calling recv twice must not leak the first allocation.
     *
     * Strategy: perform the double-recv and full cleanup under the
     * tracking allocator, then verify that every allocation was freed.
     * A leak means s_count_active_allocs() > 0 after all cleanup.
     */
    {
        struct s2n_config *config = NULL;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_enable_quic(config));

        struct s2n_connection *conn = NULL;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* First recv — allocates buffer for peer_quic_transport_parameters */
        {
            struct s2n_stuffer extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&extension, FIRST_PARAMS, sizeof(FIRST_PARAMS)));

            EXPECT_SUCCESS(s2n_quic_transport_parameters_extension.recv(conn, &extension));
            EXPECT_EQUAL(conn->peer_quic_transport_parameters.size, sizeof(FIRST_PARAMS));
            EXPECT_BYTEARRAY_EQUAL(conn->peer_quic_transport_parameters.data,
                    FIRST_PARAMS, sizeof(FIRST_PARAMS));

            EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        }

        /* Second recv — simulates HRR. With the bug (s2n_alloc), this
         * orphans the first allocation. With the fix (s2n_realloc),
         * the first buffer is freed or reused. */
        {
            struct s2n_stuffer extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&extension, SECOND_PARAMS, sizeof(SECOND_PARAMS)));

            EXPECT_SUCCESS(s2n_quic_transport_parameters_extension.recv(conn, &extension));
            EXPECT_EQUAL(conn->peer_quic_transport_parameters.size, sizeof(SECOND_PARAMS));
            EXPECT_BYTEARRAY_EQUAL(conn->peer_quic_transport_parameters.data,
                    SECOND_PARAMS, sizeof(SECOND_PARAMS));

            EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        }

        /* Clean up everything */
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* KEY ASSERTION: every allocation must have been freed.
     * If s2n_alloc was used (the bug), the first transport parameters
     * allocation is orphaned and s_count_active_allocs() will be > 0.
     * If s2n_realloc was used (the fix), all allocations are accounted for. */
    EXPECT_EQUAL(s_count_active_allocs(), 0);

    /* Restore real callbacks before END_TEST cleanup */
    {
        s2n_mem_init_callback mem_init_cb = NULL;
        s2n_mem_cleanup_callback mem_cleanup_cb = NULL;
        s2n_mem_malloc_callback unused_malloc = NULL;
        s2n_mem_free_callback unused_free = NULL;
        EXPECT_OK(s2n_mem_get_callbacks(&mem_init_cb, &mem_cleanup_cb,
                &unused_malloc, &unused_free));
        EXPECT_OK(s2n_mem_override_callbacks(mem_init_cb, mem_cleanup_cb,
                s_real_malloc, s_real_free));
    }

    END_TEST();
}
