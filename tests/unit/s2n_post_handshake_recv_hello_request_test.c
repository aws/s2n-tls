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

#include "api/unstable/renegotiate.h"
#include "s2n_test.h"
#include "testlib/s2n_mem_testlib.h"
#include "testlib/s2n_post_handshake_testlib.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_safety.h"

#define S2N_TEST_MESSAGE_COUNT 5

static size_t hello_request_count = 0;
static int s2n_hello_request_cb(struct s2n_connection *conn, void *ctx, s2n_renegotiate_response *response)
{
    hello_request_count++;
    *response = S2N_RENEGOTIATE_IGNORE;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config, s2n_hello_request_cb, NULL));

    /* HelloRequest messages are 4 bytes (header only). Only small fragment sizes
     * meaningfully exercise fragmentation for this scenario. */
    const uint32_t fragment_sizes[] = {
        1,
        2,
        TLS_HANDSHAKE_HEADER_LENGTH,
        TLS_HANDSHAKE_HEADER_LENGTH + 1,
    };

    /* Test: client receives empty post-handshake messages (HelloRequests)
     *
     * There is no server version of this test because there are no empty post-handshake messages
     * valid for the server to accept.
     */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_test_init_sender_and_receiver(config, server, client, &io_pair));

        /* HelloRequests are ignored if secure_renegotiation isn't set */
        client->secure_renegotiation = true;

        /* Write HelloRequest messages */
        DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&messages, 0));
        for (size_t i = 0; i < S2N_TEST_MESSAGE_COUNT; i++) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&messages, TLS_HELLO_REQUEST));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&messages, 0));
        }

        DEFER_CLEANUP(struct s2n_mem_test_cb_scope mem_ctx = { 0 }, s2n_mem_test_free_callbacks);
        EXPECT_OK(s2n_mem_test_init_callbacks(&mem_ctx));

        hello_request_count = 0;
        EXPECT_OK(s2n_test_send_records(server, messages, fragment_size));
        EXPECT_OK(s2n_test_basic_recv(server, client));
        EXPECT_EQUAL(hello_request_count, S2N_TEST_MESSAGE_COUNT);
        EXPECT_OK(s2n_mem_test_assert_malloc_count(0));

        EXPECT_OK(s2n_mem_test_wipe_callbacks());
        hello_request_count = 0;
        EXPECT_OK(s2n_test_send_records(server, messages, fragment_size));
        EXPECT_OK(s2n_test_blocking_recv(server, client, &io_pair));
        EXPECT_EQUAL(hello_request_count, S2N_TEST_MESSAGE_COUNT);
        EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
    }

    END_TEST();
}
