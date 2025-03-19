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
#include "tls/s2n_handshake.h"
#include "tls/s2n_tls.h"

#define UINT24_MAX ((1 << 24) - 1)

static S2N_RESULT s2n_test_handshake_finish_header(uint32_t handshake_message_length)
{
    DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&stuffer, 0));

    uint32_t stuffer_size = TLS_HANDSHAKE_HEADER_LENGTH + handshake_message_length;
    RESULT_GUARD_POSIX(s2n_stuffer_skip_write(&stuffer, stuffer_size));
    RESULT_GUARD_POSIX(s2n_handshake_finish_header(&stuffer));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_handshake_set_finished_len */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        const uint8_t max_len = sizeof(conn->handshake.client_finished);

        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_set_finished_len(NULL, 0), S2N_ERR_NULL);

        /* Length must be less than available memory */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_set_finished_len(conn, UINT8_MAX), S2N_ERR_SAFETY);
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_set_finished_len(conn, max_len + 1), S2N_ERR_SAFETY);

        /* Length must be greater than zero */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_set_finished_len(conn, 0), S2N_ERR_SAFETY);

        /* Length can change from zero to a valid length */
        EXPECT_EQUAL(conn->handshake.finished_len, 0);
        EXPECT_OK(s2n_handshake_set_finished_len(conn, max_len));
        EXPECT_EQUAL(conn->handshake.finished_len, max_len);

        /* Length can't change if already set.
         * This method will be called when calculating both the client and server finished / verify_data.
         * Both client and server should have the same length, or something has gone wrong in our implementation.
         */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_set_finished_len(conn, max_len - 1), S2N_ERR_SAFETY);
    };

    /* Test: s2n_handshake_finish_header */
    {
        /* When handshake meesage size is larger than uint16_max */
        EXPECT_OK(s2n_test_handshake_finish_header(UINT16_MAX + 1));

        /* When handshake message size is larger than uint24_max */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_handshake_finish_header(UINT24_MAX + 1), S2N_ERR_INTEGER_OVERFLOW);
    }

    END_TEST();
}
