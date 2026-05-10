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
#include "testlib/s2n_post_handshake_testlib.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_safety.h"

#define S2N_TEST_MESSAGE_COUNT 3

static size_t tickets_count = 0;
static int s2n_ticket_count_cb(struct s2n_connection *conn, void *ctx, struct s2n_session_ticket *ticket)
{
    tickets_count++;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

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

    /* NewSessionTicket messages are larger than KeyUpdates and vary in size,
     * but are still smaller than S2N_DEFAULT_FRAGMENT_LENGTH (8087). A fragment
     * size that large never causes fragmentation, and unfragmented receive is
     * already covered by every other handshake test in the suite.
     *
     * Fragment size 2 is dropped because it probes the same
     * maximally-fragmented code path as fragment size 1. */
    const uint32_t fragment_sizes[] = {
        1,
        TLS_HANDSHAKE_HEADER_LENGTH,
        TLS_HANDSHAKE_HEADER_LENGTH + 1,
    };

    /* Test: client receives large post-handshake messages (NewSessionTickets)
     *
     * There is no server version of this test because there are no large post-handshake messages
     * valid for the server to accept.
     *
     * s2n_test_blocking_recv delivers data one byte at a time, which is much slower
     * than s2n_test_basic_recv. The "resume across byte-sized IO boundaries" property
     * being tested is independent of the record fragment size, so we only exercise
     * blocking_recv at the extremes of the fragment_sizes list (maximally fragmented
     * and least fragmented) rather than at every size.
     */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];
        bool run_blocking_recv = (frag_i == 0 || frag_i == s2n_array_len(fragment_sizes) - 1);

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_test_init_sender_and_receiver(config, server, client, &io_pair));

        /* Write NewSessionTicket message */
        DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&messages, 0));
        for (size_t i = 0; i < S2N_TEST_MESSAGE_COUNT; i++) {
            server->tickets_to_send++;
            EXPECT_OK(s2n_tls13_server_nst_write(server, &messages));
        }

        tickets_count = 0;
        EXPECT_OK(s2n_test_send_records(server, messages, fragment_size));
        EXPECT_OK(s2n_test_basic_recv(server, client));
        EXPECT_EQUAL(tickets_count, S2N_TEST_MESSAGE_COUNT);

        if (run_blocking_recv) {
            tickets_count = 0;
            EXPECT_OK(s2n_test_send_records(server, messages, fragment_size));
            EXPECT_OK(s2n_test_blocking_recv(server, client, &io_pair));
            EXPECT_EQUAL(tickets_count, S2N_TEST_MESSAGE_COUNT);
        }
    }

    /* Test: client receives large post-handshake messages of different sizes (NewSessionTickets)
     *
     * There is no server version of this test because there are no large post-handshake messages
     * valid for the server to accept.
     *
     * This scenario tests that NSTs of varying sizes in a fragmented stream all
     * get processed correctly. That property is independent of the specific
     * fragment size used, so we only exercise it at a single size rather than
     * looping over all fragment_sizes.
     */
    {
        uint32_t fragment_size = TLS_HANDSHAKE_HEADER_LENGTH + 1;

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_test_init_sender_and_receiver(config, server, client, &io_pair));
        server->server_max_early_data_size = 10;

        size_t total_size = 0;
        DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&messages, 0));
        for (size_t i = 0; i < 3; i++) {
            /* Write a basic NewSessionTicket */
            server->server_max_early_data_size_overridden = false;
            server->tickets_to_send++;
            EXPECT_OK(s2n_tls13_server_nst_write(server, &messages));
            size_t min_length = s2n_stuffer_data_available(&messages) - total_size;
            total_size += min_length;

            /* Write a NewSesionTicket with early data enabled
             * so that the early_data_indication extension is included
             * and the message is therefore longer.
             */
            server->server_max_early_data_size_overridden = true;
            server->tickets_to_send++;
            EXPECT_OK(s2n_tls13_server_nst_write(server, &messages));
            size_t max_length = s2n_stuffer_data_available(&messages) - total_size;
            EXPECT_TRUE(max_length > min_length);
            total_size += max_length;
        }

        tickets_count = 0;
        EXPECT_OK(s2n_test_send_records(server, messages, fragment_size));
        EXPECT_OK(s2n_test_basic_recv(server, client));
        EXPECT_EQUAL(tickets_count, server->tickets_to_send);

        /* Scenario 1 already covers blocking_recv at two fragment sizes. The
         * "blocking IO resume works" property does not depend on message-size
         * variance, so we do not re-exercise blocking_recv here. */
    }

    END_TEST();
}
