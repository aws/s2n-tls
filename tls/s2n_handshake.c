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

#include "error/s2n_errno.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_record.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

int s2n_handshake_write_header(struct s2n_connection *conn, uint8_t message_type)
{
    if (s2n_stuffer_data_available(&conn->handshake.io)) {
        S2N_ERROR(S2N_ERR_HANDSHAKE_STATE);
    }

    /* Write the message header */
    GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, message_type));

    /* Leave the length blank for now */
    uint16_t length = 0;
    GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, length));

    return 0;
}

int s2n_handshake_finish_header(struct s2n_connection *conn)
{
    uint16_t length = s2n_stuffer_data_available(&conn->handshake.io);
    if (length < TLS_HANDSHAKE_HEADER_LENGTH) {
        S2N_ERROR(S2N_ERR_SIZE_MISMATCH);
    }

    uint16_t payload = length - TLS_HANDSHAKE_HEADER_LENGTH;

    /* Write the message header */
    GUARD(s2n_stuffer_rewrite(&conn->handshake.io));
    GUARD(s2n_stuffer_skip_write(&conn->handshake.io, 1));
    GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, payload));
    GUARD(s2n_stuffer_skip_write(&conn->handshake.io, payload));

    return 0;
}

int s2n_handshake_parse_header(struct s2n_connection *conn, uint8_t * message_type, uint32_t * length)
{
    if (s2n_stuffer_data_available(&conn->handshake.io) < TLS_HANDSHAKE_HEADER_LENGTH) {
        S2N_ERROR(S2N_ERR_SIZE_MISMATCH);
    }

    /* read the message header */
    GUARD(s2n_stuffer_read_uint8(&conn->handshake.io, message_type));
    GUARD(s2n_stuffer_read_uint24(&conn->handshake.io, length));

    return 0;
}

int s2n_handshake_get_hash_state(struct s2n_connection *conn, s2n_hash_algorithm hash_alg, struct s2n_hash_state *hash_state)
{
    switch (hash_alg) {
    case S2N_HASH_MD5:
        *hash_state = conn->handshake.md5;
        break;
    case S2N_HASH_SHA1:
        *hash_state = conn->handshake.sha1;
        break;
    case S2N_HASH_SHA224:
        *hash_state = conn->handshake.sha224;
        break;
    case S2N_HASH_SHA256:
        *hash_state = conn->handshake.sha256;
        break;
    case S2N_HASH_SHA384:
        *hash_state = conn->handshake.sha384;
        break;
    case S2N_HASH_SHA512:
        *hash_state = conn->handshake.sha512;
        break;
    case S2N_HASH_MD5_SHA1:
        *hash_state = conn->handshake.md5_sha1;
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }
    return 0;
}
