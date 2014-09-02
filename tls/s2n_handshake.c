/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdint.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_record.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

int s2n_handshake_write_header(struct s2n_connection *conn, uint8_t message_type, const char **err)
{
    if (s2n_stuffer_data_available(&conn->handshake.io)) {
        *err = "starting a handshake message before previous one is sent";
        return -1;
    }

    /* Write the message header */
    GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, message_type, err));

    /* Leave the length blank for now */
    uint16_t length = 0;
    GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, length, err));

    return 0;
}

int s2n_handshake_finish_header(struct s2n_connection *conn, const char **err)
{
    uint16_t length = s2n_stuffer_data_available(&conn->handshake.io);
    if (length < TLS_HANDSHAKE_HEADER_LENGTH) {
        *err = "finishing a record that is too short";
        return -1;
    }

    uint16_t payload = length - TLS_HANDSHAKE_HEADER_LENGTH;

    /* Write the message header */
    GUARD(s2n_stuffer_rewrite(&conn->handshake.io, err));
    GUARD(s2n_stuffer_skip_write(&conn->handshake.io, 1, err));
    GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, payload, err));
    GUARD(s2n_stuffer_skip_write(&conn->handshake.io, payload, err));

    return 0;
}

int s2n_handshake_parse_header(struct s2n_connection *conn, uint8_t *message_type, uint32_t *length, const char **err)
{
    if (s2n_stuffer_data_available(&conn->handshake.io) < TLS_HANDSHAKE_HEADER_LENGTH) {
        *err = "parsing a handshake message that is too short";
        return -1;
    }

    /* read the message header */
    GUARD(s2n_stuffer_read_uint8(&conn->handshake.io, message_type, err));
    GUARD(s2n_stuffer_read_uint24(&conn->handshake.io, length, err));

    return 0;
}
