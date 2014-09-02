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

#include <s2n.h>
#include <time.h>

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_alerts.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

/* From RFC5246 7.4.1.2. */
#define S2N_TLS_COMPRESSION_METHOD_NULL 0

int s2n_server_hello_recv(struct s2n_connection *conn, const char **err)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    uint8_t compression_method;
    uint8_t session_id[S2N_TLS_SESSION_ID_LEN];
    uint8_t session_id_len;
    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    GUARD(s2n_stuffer_read_bytes(in, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN, err));

    conn->server_protocol_version = (protocol_version[0] * 10) + protocol_version[1];

    if (conn->server_protocol_version > conn->actual_protocol_version) {
        GUARD(s2n_queue_reader_unsupported_protocol_version_alert(conn, err));
        *err = "Server negotiated a bad protocol version";
        return -1;
    }
    conn->actual_protocol_version = conn->server_protocol_version;
    conn->actual_protocol_version_established = 1;

    /* Verify that the protocol version is sane */
    if (conn->actual_protocol_version < S2N_SSLv3 || conn->actual_protocol_version > S2N_TLS12) {
        *err = "Server negotiated a bad protocol version";
        return -1;
    }

    conn->pending.signature_digest_alg = S2N_HASH_MD5_SHA1;
    if (conn->actual_protocol_version == S2N_TLS12) {
        conn->pending.signature_digest_alg = S2N_HASH_SHA1;
    }

    GUARD(s2n_stuffer_read_bytes(in, conn->pending.server_random, S2N_TLS_RANDOM_DATA_LEN, err));
    GUARD(s2n_stuffer_read_uint8(in, &session_id_len, err));

    if (session_id_len > S2N_TLS_SESSION_ID_LEN) {
        *err = "Session ID is too long";
        return -1;
    }

    GUARD(s2n_stuffer_read_bytes(in, session_id, session_id_len, err));
    uint8_t *cipher_suite_wire = s2n_stuffer_raw_read(in, S2N_TLS_CIPHER_SUITE_LEN, err);
    notnull_check(cipher_suite_wire);
    GUARD(s2n_set_cipher_as_client(conn, cipher_suite_wire, err));
    GUARD(s2n_stuffer_read_uint8(in, &compression_method, err));

    if (compression_method != S2N_TLS_COMPRESSION_METHOD_NULL) {
        *err = "Non-null compression method is not supported";
        return -1;
    }

    conn->handshake.next_state = SERVER_CERT;

    return 0;
}

int s2n_server_hello_send(struct s2n_connection *conn, const char **err)
{
    uint32_t gmt_unix_time = time(NULL);
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_stuffer server_random;
    struct s2n_blob b;
    uint8_t session_id_len = 0;
    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    b.data = conn->pending.server_random;
    b.size = S2N_TLS_RANDOM_DATA_LEN;

    /* Create the server random data */
    GUARD(s2n_stuffer_init(&server_random, &b, err));
    GUARD(s2n_stuffer_write_uint32(&server_random, gmt_unix_time, err));
    GUARD(s2n_stuffer_write_random_data(&server_random, 28, err));

    if (conn->client_protocol_version < conn->server_protocol_version) {
        conn->actual_protocol_version = conn->client_protocol_version;
    }

    protocol_version[0] = conn->actual_protocol_version / 10;
    protocol_version[1] = conn->actual_protocol_version % 10;

    conn->pending.signature_digest_alg = S2N_HASH_MD5_SHA1;
    if (conn->actual_protocol_version == S2N_TLS12) {
        conn->pending.signature_digest_alg = S2N_HASH_SHA1;
    }

    GUARD(s2n_stuffer_write_bytes(out, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN, err));
    GUARD(s2n_stuffer_write_bytes(out, conn->pending.server_random, S2N_TLS_RANDOM_DATA_LEN, err));
    GUARD(s2n_stuffer_write_uint8(out, session_id_len, err));
    GUARD(s2n_stuffer_write_bytes(out, conn->pending.cipher_suite->value, S2N_TLS_CIPHER_SUITE_LEN, err));
    GUARD(s2n_stuffer_write_uint8(out, S2N_TLS_COMPRESSION_METHOD_NULL, err));

    conn->actual_protocol_version_established = 1;
    conn->handshake.next_state = SERVER_CERT;

    return 0;
}
