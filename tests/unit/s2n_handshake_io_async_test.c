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

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_result.h"

/* Get access to s2n_handshake_read_io */
#include "tls/s2n_handshake_io.c"

bool async_blocked = false;
size_t blocking_handler_count = 0;
static int s2n_blocking_handler(struct s2n_connection *conn)
{
    blocking_handler_count++;
    if (async_blocked) {
        POSIX_BAIL(S2N_ERR_ASYNC_BLOCKED);
    }
    return S2N_SUCCESS;
}

static int s2n_error_handler(struct s2n_connection *conn)
{
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Async blocking errors block handshake negotiation */
    {
        const size_t repeat_count = 10;

        DEFER_CLEANUP(struct s2n_stuffer io_buffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&io_buffer, 0));

        /* Write handles async blocking */
        {
            tls13_state_machine[CLIENT_HELLO].handler[S2N_CLIENT] = s2n_blocking_handler;
            tls13_state_machine[SERVER_HELLO].handler[S2N_CLIENT] = s2n_error_handler;

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(NULL, &io_buffer, conn));
            EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));

            /* Consistently blocks */
            async_blocked = true;
            blocking_handler_count = 0;
            for (size_t i = 0; i < repeat_count; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked), S2N_ERR_ASYNC_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_APPLICATION_INPUT);
                EXPECT_EQUAL(s2n_stuffer_data_available(&io_buffer), 0);
            }
            EXPECT_EQUAL(blocking_handler_count, repeat_count);

            /* If unblocked, continues. Fails to read next message because there is no next message. */
            async_blocked = false;
            blocking_handler_count = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked), S2N_ERR_IO);
            EXPECT_EQUAL(blocking_handler_count, 1);

            /* Only wrote one record/message */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_buffer), S2N_TLS_RECORD_HEADER_LENGTH + TLS_HANDSHAKE_HEADER_LENGTH);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Use the output of writing to test reading */
        EXPECT_SUCCESS(s2n_stuffer_reread(&io_buffer));

        /* Read handles async blocking */
        {
            state_machine[CLIENT_HELLO].handler[S2N_SERVER] = s2n_blocking_handler;
            state_machine[SERVER_HELLO].handler[S2N_SERVER] = s2n_error_handler;

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&io_buffer, NULL, conn));

            /* Consistently blocks */
            async_blocked = true;
            blocking_handler_count = 0;
            for (size_t i = 0; i < repeat_count; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked), S2N_ERR_ASYNC_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_APPLICATION_INPUT);
                EXPECT_EQUAL(s2n_stuffer_data_available(&io_buffer), 0);
            }
            EXPECT_EQUAL(blocking_handler_count, repeat_count);

            /* If unblocked, continues */
            async_blocked = false;
            blocking_handler_count = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked), S2N_ERR_UNIMPLEMENTED);
            EXPECT_EQUAL(blocking_handler_count, 1);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    END_TEST();
}
