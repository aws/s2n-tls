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
#include <string.h>
#include <time.h>

#include <s2n.h>

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_record.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_prf.h"

#include "crypto/s2n_cipher.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

struct s2n_connection *s2n_connection_new(s2n_mode mode, const char **err)
{
    struct s2n_blob blob;
    struct s2n_connection *conn;

    if (s2n_alloc(&blob, sizeof(struct s2n_connection), err)) {
        return NULL;
    }

    if (s2n_blob_zero(&blob, err) < 0) {
        return NULL;
    }

    /* Cast 'through' void to acknowledge that we are changing alignment,
     * which is ok, as blob.data is always aligned.
     */
    conn = (struct s2n_connection *)(void *)blob.data;
    conn->mode = mode;
    conn->config = &s2n_default_config;

    /* Allocate the fixed-size stuffers */
    blob.data = conn->alert_in_data;
    blob.size = S2N_ALERT_LENGTH;
    if (s2n_stuffer_init(&conn->alert_in, &blob, err) < 0) {
        return NULL;
    }
    blob.data = conn->reader_alert_out_data;
    blob.size = S2N_ALERT_LENGTH;
    if (s2n_stuffer_init(&conn->reader_alert_out, &blob, err) < 0) {
        return NULL;
    }
    blob.data = conn->writer_alert_out_data;
    blob.size = S2N_ALERT_LENGTH;
    if (s2n_stuffer_init(&conn->writer_alert_out, &blob, err) < 0) {
        return NULL;
    }
    if (s2n_stuffer_alloc(&conn->out, S2N_MAXIMUM_RECORD_LENGTH, err) < 0) {
        return NULL;
    }

    /* Initialize the growable stuffers. Zero length at first, but the resize
     * in _wipe will fix that 
     */
    blob.data = conn->header_in_data;
    blob.size = S2N_TLS_RECORD_HEADER_LENGTH;
    if (s2n_stuffer_init(&conn->header_in, &blob, err) < 0) {
        return NULL;
    }
    if (s2n_stuffer_growable_alloc(&conn->in, 0, err) < 0) {
        return NULL;
    }
    if (s2n_stuffer_growable_alloc(&conn->handshake.io, 0, err) < 0) {
        return NULL;
    }

    if (s2n_connection_wipe(conn, err) < 0) {
        return NULL;
    }

    return conn;
}

int s2n_shutdown(struct s2n_connection *conn, int *more, const char **err)
{
    /* Write any pending I/O */
    GUARD(s2n_flush(conn, more, err));

    GUARD(s2n_queue_writer_close_alert(conn, err));

    /* Write the alert message out */
    GUARD(s2n_flush(conn, more, err));

    return 0;
}

int s2n_connection_free(struct s2n_connection *conn, const char **err)
{
    struct s2n_blob blob;

    GUARD(s2n_dh_params_free(&conn->pending.server_dh_params, err));
    GUARD(s2n_dh_params_free(&conn->active.server_dh_params, err));
    GUARD(s2n_stuffer_free(&conn->in, err));
    GUARD(s2n_stuffer_free(&conn->out, err));
    GUARD(s2n_stuffer_free(&conn->handshake.io, err));

    blob.data = (uint8_t *) conn;
    blob.size = sizeof(struct s2n_connection);

    return s2n_free(&blob, err);
}

int s2n_connection_set_config(struct s2n_connection *conn, struct s2n_config *config, const char **err)
{
    conn->config = config;
    return 0;
}

int s2n_connection_wipe(struct s2n_connection *conn, const char **err)
{
    /* First make a copy of everything we'd like to save, which isn't very
     * much.
     */
    int mode = conn->mode;
    struct s2n_config *config = conn->config;
    struct s2n_stuffer alert_in;
    struct s2n_stuffer reader_alert_out;
    struct s2n_stuffer writer_alert_out;
    struct s2n_stuffer handshake_io;
    struct s2n_stuffer header_in;
    struct s2n_stuffer in;
    struct s2n_stuffer out;

    /* Wipe all of the sensitive stuff */
    GUARD(s2n_stuffer_wipe(&conn->alert_in, err));
    GUARD(s2n_stuffer_wipe(&conn->reader_alert_out, err));
    GUARD(s2n_stuffer_wipe(&conn->writer_alert_out, err));
    GUARD(s2n_stuffer_wipe(&conn->handshake.io, err));
    GUARD(s2n_stuffer_wipe(&conn->header_in, err));
    GUARD(s2n_stuffer_wipe(&conn->in, err));
    GUARD(s2n_stuffer_wipe(&conn->out, err));

    /* Allocate or resize to their original sizes */
    GUARD(s2n_stuffer_resize(&conn->in, S2N_MAXIMUM_FRAGMENT_LENGTH, err));

    /* Allocate memory for handling handshakes */
    GUARD(s2n_stuffer_resize(&conn->handshake.io, S2N_MAXIMUM_RECORD_LENGTH, err));

    /* Clone the stuffers */
    /* ignore gcc 4.7 address warnings because dest is allocated on the stack */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress"
    memcpy_check(&alert_in, &conn->alert_in, sizeof(struct s2n_stuffer));
    memcpy_check(&reader_alert_out, &conn->reader_alert_out, sizeof(struct s2n_stuffer));
    memcpy_check(&writer_alert_out, &conn->writer_alert_out, sizeof(struct s2n_stuffer));
    memcpy_check(&handshake_io, &conn->handshake.io, sizeof(struct s2n_stuffer));
    memcpy_check(&header_in, &conn->header_in, sizeof(struct s2n_stuffer));
    memcpy_check(&in, &conn->in, sizeof(struct s2n_stuffer));
    memcpy_check(&out, &conn->out, sizeof(struct s2n_stuffer));
#pragma GCC diagnostic pop

    /* Zero the whole connection structure */
    if (memset(conn, 0, sizeof(struct s2n_connection)) != conn) {
        *err = "Could not zero the connection";
        return -1;
    }

    conn->mode = mode;
    conn->config = config;
    conn->active.cipher_suite = &s2n_null_cipher_suite;
    conn->server = &conn->active;
    conn->client = &conn->active;
    conn->max_fragment_length = S2N_MAXIMUM_FRAGMENT_LENGTH;
    conn->handshake.state = CLIENT_HELLO;
    GUARD(s2n_hash_init(&conn->handshake.client_md5, S2N_HASH_MD5, err));
    GUARD(s2n_hash_init(&conn->handshake.client_sha1, S2N_HASH_SHA1, err));
    GUARD(s2n_hash_init(&conn->handshake.client_sha256, S2N_HASH_SHA256, err));
    GUARD(s2n_hash_init(&conn->handshake.server_md5, S2N_HASH_MD5, err));
    GUARD(s2n_hash_init(&conn->handshake.server_sha1, S2N_HASH_SHA1, err));
    GUARD(s2n_hash_init(&conn->handshake.server_sha256, S2N_HASH_SHA256, err));

    memcpy_check(&conn->alert_in, &alert_in, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->reader_alert_out, &reader_alert_out, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->writer_alert_out, &writer_alert_out, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->handshake.io, &handshake_io, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->header_in, &header_in, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->in, &in, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->out, &out, sizeof(struct s2n_stuffer));

    /* Set everything to the highest version at first */
    conn->server_protocol_version = s2n_highest_protocol_version;
    conn->client_protocol_version = s2n_highest_protocol_version;
    conn->actual_protocol_version = s2n_highest_protocol_version;

    return 0;
}

int s2n_connection_set_read_fd(struct s2n_connection *conn, int rfd, const char **err)
{
    conn->readfd = rfd;
    return 0;
}

int s2n_connection_set_write_fd(struct s2n_connection *conn, int wfd, const char **err)
{
    conn->writefd = wfd;
    return 0;
}

int s2n_connection_set_fd(struct s2n_connection *conn, int fd, const char **err)
{
    GUARD(s2n_connection_set_read_fd(conn, fd, err));
    GUARD(s2n_connection_set_write_fd(conn, fd, err));
    return 0;
}

uint64_t s2n_connection_get_wire_bytes_in(struct s2n_connection *conn)
{
    return conn->wire_bytes_in;
}

uint64_t s2n_connection_get_wire_bytes_out(struct s2n_connection *conn)
{
    return conn->wire_bytes_out;
}

const char *s2n_connection_get_cipher(struct s2n_connection *conn, const char **err)
{
    return conn->active.cipher_suite->name;
}

int s2n_connection_get_client_protocol_version(struct s2n_connection *conn, const char **err)
{
    return conn->client_protocol_version;
}

int s2n_connection_get_server_protocol_version(struct s2n_connection *conn, const char **err)
{
    return conn->server_protocol_version;
}

int s2n_connection_get_actual_protocol_version(struct s2n_connection *conn, const char **err)
{
    return conn->actual_protocol_version;
}

int s2n_connection_was_client_hello_sslv2(struct s2n_connection *conn)
{
    return conn->handshake.was_client_hello_sslv2;
}

int s2n_connection_get_alert(struct s2n_connection *conn, const char **err)
{
    *err = "No alert code";
    uint8_t alert_code = -1;
    if (s2n_stuffer_data_available(&conn->alert_in) == 2) {
        *err = "";
        GUARD(s2n_stuffer_read_uint8(&conn->alert_in, &alert_code, err));
        GUARD(s2n_stuffer_read_uint8(&conn->alert_in, &alert_code, err));
    }
    return alert_code;
}

int s2n_set_server_name(struct s2n_connection *conn, const char *server_name, const char **err)
{
    if (conn->mode != S2N_CLIENT) {
        *err = "Cannot set server name except as client";
        return -1;
    }

    int len = strlen(server_name);
    if (len > 255) {
        *err = "Server name is longer than 255";
        return -1;
    }

    memcpy_check(conn->server_name, server_name, len);

    return 0;
}

const char *s2n_get_server_name(struct s2n_connection *conn, const char **err)
{
    if (strlen(conn->server_name) == 0) {
        return NULL;
    }

    return conn->server_name;
}
