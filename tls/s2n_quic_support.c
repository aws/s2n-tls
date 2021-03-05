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

#include "tls/s2n_quic_support.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls.h"

#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

/* When reading and writing records with TCP, S2N sets its input and output buffers
 * to the maximum record fragment size to prevent resizing those buffers later.
 *
 * However, because S2N with QUIC reads and writes messages instead of records,
 * the "maximum size" for the input and output buffers would be the maximum message size: 64k.
 * Since most messages are MUCH smaller than that (<3k), setting the buffer that large is wasteful.
 *
 * Instead, we intentionally choose a smaller size and accept that an abnormally large message
 * could cause the buffer to resize. */
#define S2N_EXPECTED_QUIC_MESSAGE_SIZE S2N_DEFAULT_FRAGMENT_LENGTH

S2N_RESULT s2n_read_in_bytes(struct s2n_connection *conn, struct s2n_stuffer *output, uint32_t length);

int s2n_config_enable_quic(struct s2n_config *config)
{
    POSIX_ENSURE_REF(config);
    config->quic_enabled = true;
    return S2N_SUCCESS;
}

int s2n_connection_set_quic_transport_parameters(struct s2n_connection *conn,
        const uint8_t *data_buffer, uint16_t data_len)
{
    POSIX_ENSURE_REF(conn);

    POSIX_GUARD(s2n_free(&conn->our_quic_transport_parameters));
    POSIX_GUARD(s2n_alloc(&conn->our_quic_transport_parameters, data_len));
    POSIX_CHECKED_MEMCPY(conn->our_quic_transport_parameters.data, data_buffer, data_len);

    return S2N_SUCCESS;
}

int s2n_connection_get_quic_transport_parameters(struct s2n_connection *conn,
        const uint8_t **data_buffer, uint16_t *data_len)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(data_buffer);
    POSIX_ENSURE_REF(data_len);

    *data_buffer = conn->peer_quic_transport_parameters.data;
    *data_len = conn->peer_quic_transport_parameters.size;

    return S2N_SUCCESS;
}

int s2n_connection_set_secret_callback(struct s2n_connection *conn, s2n_secret_cb cb_func, void *ctx)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(cb_func);

    conn->secret_cb = cb_func;
    conn->secret_cb_context = ctx;

    return S2N_SUCCESS;
}

/* When using QUIC, S2N reads unencrypted handshake messages instead of encrypted records.
 * This method sets up the S2N input buffers to match the results of using s2n_read_full_record.
 */
S2N_RESULT s2n_quic_read_handshake_message(struct s2n_connection *conn, uint8_t *message_type)
{
    RESULT_ENSURE_REF(conn);

    /* Allocate stuffer space now so that we don't have to realloc later in the handshake. */
    RESULT_GUARD_POSIX(s2n_stuffer_resize_if_empty(&conn->in, S2N_EXPECTED_QUIC_MESSAGE_SIZE));

    RESULT_GUARD(s2n_read_in_bytes(conn, &conn->handshake.io, TLS_HANDSHAKE_HEADER_LENGTH));

    uint32_t message_len;
    RESULT_GUARD_POSIX(s2n_handshake_parse_header(conn, message_type, &message_len));
    RESULT_GUARD_POSIX(s2n_stuffer_reread(&conn->handshake.io));

    RESULT_ENSURE(message_len < S2N_MAXIMUM_HANDSHAKE_MESSAGE_LENGTH, S2N_ERR_BAD_MESSAGE);
    RESULT_GUARD(s2n_read_in_bytes(conn, &conn->in, message_len));

    return S2N_RESULT_OK;
}

/* When using QUIC, S2N writes unencrypted handshake messages instead of encrypted records.
 * This method sets up the S2N output buffer to match the result of using s2n_record_write.
 */
S2N_RESULT s2n_quic_write_handshake_message(struct s2n_connection *conn, struct s2n_blob *in)
{
    RESULT_ENSURE_REF(conn);

    /* Allocate stuffer space now so that we don't have to realloc later in the handshake. */
    RESULT_GUARD_POSIX(s2n_stuffer_resize_if_empty(&conn->out, S2N_EXPECTED_QUIC_MESSAGE_SIZE));

    RESULT_GUARD_POSIX(s2n_stuffer_write(&conn->out, in));
    return S2N_RESULT_OK;
}
