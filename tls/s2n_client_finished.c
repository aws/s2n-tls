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
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13_handshake.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

int s2n_client_finished_recv(struct s2n_connection *conn)
{
    uint8_t *our_version;
    our_version = conn->handshake.client_finished;
    uint8_t *their_version = s2n_stuffer_raw_read(&conn->handshake.io, S2N_TLS_FINISHED_LEN);
    notnull_check(their_version);

    S2N_ERROR_IF(!s2n_constant_time_equals(our_version, their_version, S2N_TLS_FINISHED_LEN) || conn->handshake.rsa_failed, S2N_ERR_BAD_MESSAGE);

    return 0;
}

int s2n_client_finished_send(struct s2n_connection *conn)
{
    uint8_t *our_version;
    GUARD(s2n_prf_client_finished(conn));

    struct s2n_blob seq = {.data = conn->secure.client_sequence_number,.size = sizeof(conn->secure.client_sequence_number) };
    GUARD(s2n_blob_zero(&seq));
    our_version = conn->handshake.client_finished;

    /* Update the server to use the cipher suite */
    conn->client = &conn->secure;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        GUARD(s2n_stuffer_write_bytes(&conn->handshake.io, our_version, S2N_SSL_FINISHED_LEN));
    } else {
        GUARD(s2n_stuffer_write_bytes(&conn->handshake.io, our_version, S2N_TLS_FINISHED_LEN));
    }
    return 0;
}

int s2n_tls13_client_finished_recv(struct s2n_connection *conn) {
    eq_check(conn->actual_protocol_version, S2N_TLS13);

    uint8_t length = s2n_stuffer_data_available(&conn->handshake.io);
    S2N_ERROR_IF(length == 0, S2N_ERR_BAD_MESSAGE);

    /* read finished mac from handshake */
    struct s2n_blob wire_finished_mac = {0};
    s2n_blob_init(&wire_finished_mac, s2n_stuffer_raw_read(&conn->handshake.io, length), length);

    /* get tls13 keys */
    s2n_tls13_connection_keys(keys, conn);

    /* get transcribe hash */
    struct s2n_hash_state hash_state = {0};
    GUARD(s2n_handshake_get_hash_state(conn, keys.hash_algorithm, &hash_state));

    struct s2n_blob finished_key = {0};
    GUARD(s2n_blob_init(&finished_key, conn->handshake.client_finished, keys.size));

    s2n_tls13_key_blob(client_finished_mac, keys.size);
    GUARD(s2n_tls13_calculate_finished_mac(&keys, &finished_key, &hash_state, &client_finished_mac));

    GUARD(s2n_tls13_mac_verify(&keys, &client_finished_mac, &wire_finished_mac));

    return 0;
}

int s2n_tls13_client_finished_send(struct s2n_connection *conn) {
    eq_check(conn->actual_protocol_version, S2N_TLS13);

    /* get tls13 keys */
    s2n_tls13_connection_keys(keys, conn);

    /* get transcribe hash */
    struct s2n_hash_state hash_state = {0};
    GUARD(s2n_handshake_get_hash_state(conn, keys.hash_algorithm, &hash_state));

    /* look up finished secret key */
    struct s2n_blob finished_key = {0};
    GUARD(s2n_blob_init(&finished_key, conn->handshake.client_finished, keys.size));

    /* generate the hashed message authenticated code */
    s2n_stack_blob(client_finished_mac, keys.size, S2N_TLS13_SECRET_MAX_LEN);
    GUARD(s2n_tls13_calculate_finished_mac(&keys, &finished_key, &hash_state, &client_finished_mac));

    /* write to handshake io */
    GUARD(s2n_stuffer_write(&conn->handshake.io, &client_finished_mac));

    return 0;
}
