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

#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_mem_testlib.h"
#include "testlib/s2n_post_handshake_testlib.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t unknown_message_type = UINT8_MAX;
    const uint32_t test_large_message_size = 3001;

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

    /* Rejection tests exercise type-dispatch logic, which is independent of the
     * specific fragment size. Two sizes are plenty: one that forces fragmentation
     * and one that doesn't. */
    const uint32_t fragment_sizes[] = {
        2,
        TLS_HANDSHAKE_HEADER_LENGTH + 1,
    };
    const uint8_t modes[] = { S2N_CLIENT, S2N_SERVER };

    /* Test: client and server reject known, invalid messages (ClientHellos) */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];

        for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
            uint8_t mode = modes[mode_i];

            DEFER_CLEANUP(struct s2n_connection *receiver = s2n_connection_new(mode), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *sender = s2n_connection_new(S2N_PEER_MODE(mode)), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_sender_and_receiver(config, sender, receiver, &io_pair));

            /* Send fake ClientHello messages */
            DEFER_CLEANUP(struct s2n_stuffer message = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&message, TLS_HANDSHAKE_HEADER_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&message, TLS_CLIENT_HELLO));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&message, test_large_message_size));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&message, test_large_message_size));
            EXPECT_OK(s2n_test_send_records(sender, message, fragment_size));

            DEFER_CLEANUP(struct s2n_mem_test_cb_scope mem_ctx = { 0 }, s2n_mem_test_free_callbacks);
            EXPECT_OK(s2n_mem_test_init_callbacks(&mem_ctx));
            EXPECT_ERROR_WITH_ERRNO(s2n_test_basic_recv(sender, receiver), S2N_ERR_BAD_MESSAGE);

            /* No post-handshake message should trigger the server to allocate memory */
            if (mode == S2N_SERVER) {
                EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
            }
        }
    }

    /* Test: client and server reject unknown messages */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];

        for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
            uint8_t mode = modes[mode_i];

            DEFER_CLEANUP(struct s2n_connection *receiver = s2n_connection_new(mode), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *sender = s2n_connection_new(S2N_PEER_MODE(mode)), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_sender_and_receiver(config, sender, receiver, &io_pair));

            /* Send unknown message */
            DEFER_CLEANUP(struct s2n_stuffer message = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&message, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&message, unknown_message_type));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&message, test_large_message_size));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&message, test_large_message_size));
            EXPECT_OK(s2n_test_send_records(sender, message, fragment_size));

            DEFER_CLEANUP(struct s2n_mem_test_cb_scope mem_ctx = { 0 }, s2n_mem_test_free_callbacks);
            EXPECT_OK(s2n_mem_test_init_callbacks(&mem_ctx));
            EXPECT_ERROR_WITH_ERRNO(s2n_test_basic_recv(sender, receiver), S2N_ERR_BAD_MESSAGE);

            /* No post-handshake message should trigger the server to allocate memory */
            if (mode == S2N_SERVER) {
                EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
            }
        }
    }

    END_TEST();
}
