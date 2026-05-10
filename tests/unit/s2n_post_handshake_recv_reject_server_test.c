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
#include "tls/s2n_key_update.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_safety.h"

static size_t tickets_count = 0;
static int s2n_ticket_count_cb(struct s2n_connection *conn, void *ctx, struct s2n_session_ticket *ticket)
{
    tickets_count++;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint32_t test_large_message_size = 3001;

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_ticket_count_cb, NULL));

    /* Setup the config to handle tickets, but don't send any by default. */
    uint8_t ticket_key_name[16] = "key name";
    uint8_t ticket_key[] = "key data";
    uint64_t current_time = 0;
    EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
    EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, sizeof(ticket_key_name),
            ticket_key, sizeof(ticket_key), current_time / ONE_SEC_IN_NANOS));
    config->initial_tickets_to_send = 0;

    /* Rejection tests exercise type-dispatch and length-validation logic,
     * which is independent of the specific fragment size. Two sizes are plenty:
     * one that forces fragmentation and one that doesn't. */
    const uint32_t fragment_sizes[] = {
        2,
        TLS_HANDSHAKE_HEADER_LENGTH + 1,
    };

    /* Test: server rejects known, invalid post-handshake messages (NewSessionTickets)
     *
     * There is no client version of this test because the client accepts all supported
     * post-handshake messages.
     */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_test_init_sender_and_receiver(config, client, server, &io_pair));

        /* Send NewSessionTicket message */
        DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&messages, 0));
        client->tickets_to_send = 1;
        EXPECT_OK(s2n_tls13_server_nst_write(client, &messages));
        EXPECT_OK(s2n_test_send_records(client, messages, fragment_size));

        DEFER_CLEANUP(struct s2n_mem_test_cb_scope mem_ctx = { 0 }, s2n_mem_test_free_callbacks);
        EXPECT_OK(s2n_mem_test_init_callbacks(&mem_ctx));
        tickets_count = 0;
        EXPECT_ERROR_WITH_ERRNO(s2n_test_basic_recv(client, server), S2N_ERR_BAD_MESSAGE);
        EXPECT_EQUAL(tickets_count, 0);
        EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
    }

    /* Test: server rejects fragmented post-handshake message (KeyUpdate) with an invalid size
     *
     * This response is unique to the server because we want to prevent a malicious
     * client from forcing the server to allocate large amounts of memory.
     *
     * While we could extend the same validation to the client, the client accepts
     * a variable-sized message (NewSessionTicket) so can't really be protected.
     */
    {
        /* This test is only interesting if the message is fragmented */
        uint32_t fragment_size = 2;

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_test_init_sender_and_receiver(config, client, server, &io_pair));

        /* Write large KeyUpdate messages */
        DEFER_CLEANUP(struct s2n_stuffer message = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&message, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&message, TLS_KEY_UPDATE));
        EXPECT_SUCCESS(s2n_stuffer_write_uint24(&message, test_large_message_size));
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&message, test_large_message_size));
        EXPECT_OK(s2n_test_send_records(client, message, fragment_size));
        EXPECT_SUCCESS(s2n_update_application_traffic_keys(client, client->mode, SENDING));

        DEFER_CLEANUP(struct s2n_mem_test_cb_scope mem_ctx = { 0 }, s2n_mem_test_free_callbacks);
        EXPECT_OK(s2n_mem_test_init_callbacks(&mem_ctx));
        EXPECT_ERROR_WITH_ERRNO(s2n_test_basic_recv(client, server), S2N_ERR_BAD_MESSAGE);

        /* No post-handshake message should trigger the server to allocate memory */
        EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
    };

    END_TEST();
}
