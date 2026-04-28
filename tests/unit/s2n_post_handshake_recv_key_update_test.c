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
#include "testlib/s2n_mem_testlib.h"
#include "testlib/s2n_post_handshake_testlib.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_key_update.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_safety.h"

#define S2N_TEST_MESSAGE_COUNT 5

int s2n_key_update_write(struct s2n_blob *out);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

    /* KeyUpdate messages are 4 bytes. Only small fragment sizes meaningfully
     * exercise fragmentation for this scenario. */
    const uint32_t fragment_sizes[] = {
        1,
        2,
        S2N_MIN_SEND_BUFFER_FRAGMENT_SIZE,
        TLS_HANDSHAKE_HEADER_LENGTH,
        TLS_HANDSHAKE_HEADER_LENGTH + 1,
    };
    const uint8_t modes[] = { S2N_CLIENT, S2N_SERVER };

    /* Test: client and server receive small post-handshake messages (KeyUpdates) */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];

        for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
            uint8_t mode = modes[mode_i];

            DEFER_CLEANUP(struct s2n_connection *receiver = s2n_connection_new(mode), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *sender = s2n_connection_new(S2N_PEER_MODE(mode)), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_sender_and_receiver(config, sender, receiver, &io_pair));

            /* Write KeyUpdate message */
            struct s2n_stuffer message = { 0 };
            DEFER_CLEANUP(struct s2n_blob message_blob = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&message_blob, S2N_KEY_UPDATE_MESSAGE_SIZE));
            for (size_t i = 0; i < S2N_TEST_MESSAGE_COUNT; i++) {
                EXPECT_SUCCESS(s2n_key_update_write(&message_blob));
                EXPECT_SUCCESS(s2n_stuffer_init(&message, &message_blob));
                EXPECT_SUCCESS(s2n_stuffer_skip_write(&message, S2N_KEY_UPDATE_MESSAGE_SIZE));

                /* The TLS1.3 RFC says "Handshake messages MUST NOT span key changes".
                 * Because KeyUpdate messages trigger key changes, we cannot include multiple in one record.
                 * We must send individual KeyUpdate messages.
                 */
                EXPECT_OK(s2n_test_send_records(sender, message, fragment_size));

                /* Update the traffic keys for the next records */
                EXPECT_SUCCESS(s2n_update_application_traffic_keys(sender, sender->mode, SENDING));
            }

            /*
             * We have no mechanism to count KeyUpdates, but we can assume they are processed
             * if we successfully decrypt all records. If they were not processed,
             * then we would try to use the wrong key to decrypt the next record.
             */
            DEFER_CLEANUP(struct s2n_mem_test_cb_scope mem_ctx = { 0 }, s2n_mem_test_free_callbacks);
            EXPECT_OK(s2n_mem_test_init_callbacks(&mem_ctx));
            EXPECT_OK(s2n_test_basic_recv(sender, receiver));
            EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
        }
    }

    END_TEST();
}
