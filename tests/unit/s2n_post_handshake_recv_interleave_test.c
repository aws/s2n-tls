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
#include "testlib/s2n_post_handshake_testlib.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_key_update.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

    const uint8_t modes[] = { S2N_CLIENT, S2N_SERVER };

    /**
     *= https://www.rfc-editor.org/rfc/rfc8446#section-5.1
     *= type=test
     *#    -  Handshake messages MUST NOT be interleaved with other record
     *#       types.  That is, if a handshake message is split over two or more
     *#       records, there MUST NOT be any other records between them.
     */
    for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
        uint8_t mode = modes[mode_i];

        /* This test is only interesting if the message is fragmented */
        uint32_t fragment_size = 2;

        DEFER_CLEANUP(struct s2n_connection *receiver = s2n_connection_new(mode), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *sender = s2n_connection_new(S2N_PEER_MODE(mode)), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_test_init_sender_and_receiver(config, sender, receiver, &io_pair));

        /* Write a partial message */
        DEFER_CLEANUP(struct s2n_stuffer message = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&message, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&message, TLS_KEY_UPDATE));
        EXPECT_SUCCESS(s2n_stuffer_write_uint24(&message, S2N_KEY_UPDATE_LENGTH));
        /* Don't write the actual message body -- we want the message to be incomplete */

        /* Verify we can't receive the records: s2n_test_send_records does not send
         * the complete handshake message, so we receive the application data sent by
         * s2n_test_basic_recv in the middle of the handshake message.
         */
        EXPECT_OK(s2n_test_send_records(sender, message, fragment_size));
        EXPECT_ERROR_WITH_ERRNO(s2n_test_basic_recv(sender, receiver), S2N_ERR_BAD_MESSAGE);
    }

    END_TEST();
}
