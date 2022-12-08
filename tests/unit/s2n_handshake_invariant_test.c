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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "api/s2n.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_rsa_pss.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_handshake_io.c"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

/* A full record that has an "APPLICATION_DATA" inside according to s2n's
 * handshake message_types.
 */
uint8_t record[] = {
    /* Record type HANDSHAKE */
    0x16,
    /* Protocol version TLS 1.2 */
    0x03, 0x03,
    /* record len */
    0x00, 0x05,
    /* Type(s2n has this as expected message type for APPLICATION_DATA handler.
     * This is not a standardized value, just something s2n has hardcoded as a placeholder
     * For the APPLICATON_DATA state in the state machine.
     */
    0x00,
    /* Len */
    0x00, 0x00, 0x01,
    /* Data */
    0x00
};
static int amt_written = 0;

int s2n_app_data_in_handshake_record_recv_fn(void *io_context, uint8_t *buf, uint32_t len)
{
    int amt_left = sizeof(record) - amt_written;
    int to_write = MIN(len, amt_left);
    POSIX_CHECKED_MEMCPY(buf, record + amt_written, to_write);
    amt_written += to_write;
    return to_write;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    struct s2n_connection *conn;
    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

    /* Initialize *some* handshake type. Not terribly relevant for this test. */
    conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY;
    /* Fast forward the handshake state machine to the end of this "handshake_type".
     * APPLICATION_DATA is the 11th state for "NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY".
     */
    conn->handshake.message_number = 10;
    conn->actual_protocol_version = S2N_TLS12;
    /* Provide the crafted record to s2n's I/O */
    s2n_connection_set_recv_cb(conn, s2n_app_data_in_handshake_record_recv_fn);

    EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_read_io(conn), S2N_ERR_BAD_MESSAGE);

    s2n_connection_free(conn);
    END_TEST();
    return 0;
}
