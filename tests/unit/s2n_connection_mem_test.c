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
#include "testlib/s2n_testlib.h"

#include "tls/s2n_connection.h"
#include "utils/s2n_socket.h"

/* Get access to private mem methods */
#include "utils/s2n_mem.c"

/*
 * Before we increase this,
 * we should consider if we can reduce allocations.
 */
#define MAX_ALLOC_COUNT 100

size_t alloc_count = 0;
void* allocs_ptrs[MAX_ALLOC_COUNT] = { 0 };
uint32_t allocs[MAX_ALLOC_COUNT] = { 0 };

size_t free_count = 0;
void* frees_ptrs[MAX_ALLOC_COUNT] = { 0 };
uint32_t frees[MAX_ALLOC_COUNT] = { 0 };

static s2n_mem_malloc_callback s2n_default_mem_malloc_cb = s2n_mem_malloc_mlock_impl;
static s2n_mem_free_callback s2n_default_mem_free_cb = s2n_mem_free_mlock_impl;

int s2n_count_mem_alloc_cb(void **ptr, uint32_t requested, uint32_t *allocated)
{
    POSIX_GUARD(s2n_default_mem_malloc_cb(ptr, requested, allocated));

    if (requested > 0) {
        POSIX_ENSURE_LT(alloc_count, sizeof(allocs));
        allocs_ptrs[alloc_count] = *ptr;
        allocs[alloc_count] = requested;
        alloc_count++;
    }
    return S2N_SUCCESS;
}

int s2n_count_mem_free_cb(void *ptr, uint32_t size)
{
    if (ptr != NULL) {
        POSIX_ENSURE_LT(free_count, sizeof(frees));
        frees_ptrs[free_count] = ptr;
        frees[free_count] = size;
        free_count++;
    }

    POSIX_GUARD(s2n_default_mem_free_cb(ptr, size));
    return S2N_SUCCESS;
}

static int s2n_count_mem_init_impl(void)
{
    POSIX_GUARD(s2n_mem_init_impl());

    /* s2n_mem_init_impl overrides memory callbacks for tests,
     * so we need to set our callback here rather than with s2n_mem_set_callbacks.
     */
    s2n_default_mem_malloc_cb = s2n_mem_malloc_cb;
    s2n_mem_malloc_cb = s2n_count_mem_alloc_cb;
    s2n_default_mem_free_cb = s2n_mem_free_cb;
    s2n_mem_free_cb = s2n_count_mem_free_cb;

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    EXPECT_SUCCESS_WITHOUT_COUNT(s2n_mem_set_callbacks(s2n_count_mem_init_impl,
            s2n_mem_cleanup_cb, s2n_mem_malloc_cb, s2n_mem_free_cb));

    BEGIN_TEST();

    /* Test s2n_connection does not grow too much.
     * s2n_connection is a very large structure. We should be working to reduce its
     * size, not increasing it.
     * This test documents changes to its size for reviewers so that we can
     * make very deliberate choices about increasing memory usage.
     *
     * We can't easily enforce an exact size for s2n_connection because it varies
     * based on some settings (like how many KEM groups are supported).
     */
    {
        /* Carefully consider any increases to this number. */
        const uint16_t max_connection_size = 4150;
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
    }

    /* Test that s2n_connection_free_handshake frees all non-essential memory. */
    {
        uint32_t known_memory[] = {
                sizeof(struct s2n_connection),              /* s2n_connection - client */
                sizeof(struct s2n_connection),              /* s2n_connection - server */
                sizeof(struct s2n_crypto_parameters),       /* conn->secure - client */
                sizeof(struct s2n_crypto_parameters),       /* conn->secure - server */
                sizeof(struct s2n_socket_read_io_context),  /* read io context - client */
                sizeof(struct s2n_socket_read_io_context),  /* read io context - server */
                sizeof(struct s2n_socket_write_io_context), /* write io context - client */
                sizeof(struct s2n_socket_write_io_context), /* write io context - server */
                S2N_LARGE_FRAGMENT_LENGTH,                  /* conn->in - client */
                S2N_LARGE_FRAGMENT_LENGTH,                  /* conn->in - server */
                9116,                                       /* conn->out - client */
                8348,                                       /* conn->out - server */
        };

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        /* Any previous allocations aren't relevant to this test. */
        alloc_count = 0;
        free_count = 0;

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_connection_free_handshake(client_conn));
        EXPECT_SUCCESS(s2n_connection_free_handshake(server_conn));

        uint8_t app_data[100] = "hello world";
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_EQUAL(s2n_send(client_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
        EXPECT_EQUAL(s2n_recv(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
        EXPECT_EQUAL(s2n_send(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
        EXPECT_EQUAL(s2n_recv(client_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));

        /* Ignore any allocs with a matching free */
        for (size_t alloc_i = 0; alloc_i < alloc_count; alloc_i++) {
            for (size_t free_i = 0; free_i < free_count; free_i++) {
                if (allocs_ptrs[alloc_i] == frees_ptrs[free_i]) {
                    allocs[alloc_i] = 0;
                    break;
                }
            }
        }

        /* Ignore any allocs for a known block of memory */
        for (size_t alloc_i = 0; alloc_i < alloc_count; alloc_i++) {
            for (size_t mem_i = 0; mem_i < s2n_array_len(known_memory); mem_i++) {
                if (allocs[alloc_i] == known_memory[mem_i]) {
                    allocs[alloc_i] = 0;

                    /* Each known memory entry can only be used once.
                     * If the same amount of memory appears again, it's unexpected.
                     */
                    known_memory[mem_i] = 0;
                    break;
                }
            }
        }

        /* Any remaining unaccounted-for allocs are errors.
         *
         * To debug if this test fails:
         * See the failure message for "alloc_count" and "requested".
         *
         * Set a breakpoint in s2n_count_mem_alloc_cb before "alloc_count"
         * is incremented.
         *
         * If "requested" is NOT in "known_memory" at all,
         * set a condition on your breakpoint of "alloc_count==".
         * Use "info stack" to examine where the allocation occurs.
         *
         * If "requested" is in "known_memory" but has occurred more often than expected,
         * set a condition on your breakpoint of "requested==".
         * Use "info stack" to examine each instance where the allocation occurs.
         */
        const char message[] = "Allocation unaccounted for: alloc_count=%zu, requested=%i";
        char message_buffer[sizeof(message) + 100] = { 0 };
        for (size_t alloc_i = 0; alloc_i < alloc_count; alloc_i++) {
            if (allocs[alloc_i] != 0) {
                int r = snprintf(message_buffer, sizeof(message_buffer), message,
                        alloc_i, allocs[alloc_i]);
                EXPECT_TRUE(r < sizeof(message_buffer));
                FAIL_MSG(message_buffer);
            }
        }
    }

    END_TEST();
}
