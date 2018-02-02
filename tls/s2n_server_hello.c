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

#include <sys/param.h>

#include <s2n.h>
#include <time.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

/* From RFC5246 7.4.1.2. */
#define S2N_TLS_COMPRESSION_METHOD_NULL 0

int s2n_server_hello_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    uint8_t compression_method;
    uint8_t session_id[S2N_TLS_SESSION_ID_MAX_LEN];
    uint8_t session_id_len;
    uint16_t extensions_size;
    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    GUARD(s2n_stuffer_read_bytes(in, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

    conn->server_protocol_version = (uint8_t)(protocol_version[0] * 10) + protocol_version[1];

    if (conn->server_protocol_version < conn->config->cipher_preferences->minimum_protocol_version || conn->server_protocol_version > conn->client_protocol_version) {
        GUARD(s2n_queue_reader_unsupported_protocol_version_alert(conn));
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }
    conn->actual_protocol_version = MIN(conn->server_protocol_version, conn->client_protocol_version);
    conn->actual_protocol_version_established = 1;

    GUARD(s2n_stuffer_read_bytes(in, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_stuffer_read_uint8(in, &session_id_len));

    S2N_ERROR_IF(session_id_len > S2N_TLS_SESSION_ID_MAX_LEN, S2N_ERR_BAD_MESSAGE);

    conn->session_id_len = session_id_len;
    GUARD(s2n_stuffer_read_bytes(in, session_id, session_id_len));
    uint8_t *cipher_suite_wire = s2n_stuffer_raw_read(in, S2N_TLS_CIPHER_SUITE_LEN);
    notnull_check(cipher_suite_wire);
    GUARD(s2n_set_cipher_as_client(conn, cipher_suite_wire));
    GUARD(s2n_stuffer_read_uint8(in, &compression_method));

    S2N_ERROR_IF(compression_method != S2N_TLS_COMPRESSION_METHOD_NULL, S2N_ERR_BAD_MESSAGE);

    if (s2n_stuffer_data_available(in) >= 2) {
        GUARD(s2n_stuffer_read_uint16(in, &extensions_size));

        S2N_ERROR_IF(extensions_size > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

        struct s2n_blob extensions;
        extensions.size = extensions_size;
        extensions.data = s2n_stuffer_raw_read(in, extensions.size);
        notnull_check(extensions.data);

        GUARD(s2n_server_extensions_recv(conn, &extensions));
    }

    GUARD(s2n_conn_set_handshake_type(conn));

    if (IS_RESUMPTION_HANDSHAKE(conn->handshake.handshake_type)) {
        GUARD(s2n_prf_key_expansion(conn));
    }

    /* We've selected the cipher, update the required hashes for this connection */
    GUARD(s2n_conn_update_required_handshake_hashes(conn));

    return 0;
}

int s2n_server_hello_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_stuffer server_random;
    struct s2n_blob b, r;
    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    b.data = conn->secure.server_random;
    b.size = S2N_TLS_RANDOM_DATA_LEN;

    /* Create the server random data */
    GUARD(s2n_stuffer_init(&server_random, &b));

    r.data = s2n_stuffer_raw_write(&server_random, S2N_TLS_RANDOM_DATA_LEN);
    r.size = S2N_TLS_RANDOM_DATA_LEN;
    notnull_check(r.data);
    GUARD(s2n_get_public_random_data(&r));

    protocol_version[0] = (uint8_t)(conn->actual_protocol_version / 10);
    protocol_version[1] = (uint8_t)(conn->actual_protocol_version % 10);


    GUARD(s2n_stuffer_write_bytes(out, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));
    GUARD(s2n_stuffer_write_bytes(out, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_stuffer_write_uint8(out, conn->session_id_len));
    GUARD(s2n_stuffer_write_bytes(out, conn->session_id, conn->session_id_len));
    GUARD(s2n_stuffer_write_bytes(out, conn->secure.cipher_suite->iana_value, S2N_TLS_CIPHER_SUITE_LEN));
    GUARD(s2n_stuffer_write_uint8(out, S2N_TLS_COMPRESSION_METHOD_NULL));

    GUARD(s2n_server_extensions_send(conn, out));

    conn->actual_protocol_version_established = 1;

    return 0;
}
