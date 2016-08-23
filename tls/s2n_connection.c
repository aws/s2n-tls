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

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <s2n.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_record.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_prf.h"

#include "crypto/s2n_cipher.h"

#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_timer.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

#define GCC_VERSION (__GNUC__ * 10000 \
                     + __GNUC_MINOR__ * 100 \
                     + __GNUC_PATCHLEVEL__)

struct s2n_connection *s2n_connection_new(s2n_mode mode)
{
    struct s2n_blob blob;
    struct s2n_connection *conn;

    GUARD_PTR(s2n_alloc(&blob, sizeof(struct s2n_connection)));

    GUARD_PTR(s2n_blob_zero(&blob));

    if (mode == S2N_CLIENT) {
        /* At present s2n is not suitable for use in client mode, as it
         * does not perform any certificate validation. However it is useful
         * to use S2N in client mode for testing purposes. An environment
         * variable is required to be set for the client mode to work.
         */
        if (getenv("S2N_ENABLE_CLIENT_MODE") == NULL) {
            GUARD_PTR(s2n_free(&blob));
            S2N_ERROR_PTR(S2N_ERR_CLIENT_MODE_DISABLED);
        }
    }

    /* Cast 'through' void to acknowledge that we are changing alignment,
     * which is ok, as blob.data is always aligned.
     */
    conn = (struct s2n_connection *)(void *)blob.data;
    conn->mode = mode;
    conn->blinding = S2N_BUILT_IN_BLINDING;
    conn->config = &s2n_default_config;
    conn->close_notify_queued = 0;
    conn->session_id_len = 0;

    /* Allocate the fixed-size stuffers */
    blob.data = conn->alert_in_data;
    blob.size = S2N_ALERT_LENGTH;

    GUARD_PTR(s2n_stuffer_init(&conn->alert_in, &blob));

    blob.data = conn->reader_alert_out_data;
    blob.size = S2N_ALERT_LENGTH;

    GUARD_PTR(s2n_stuffer_init(&conn->reader_alert_out, &blob));

    blob.data = conn->writer_alert_out_data;
    blob.size = S2N_ALERT_LENGTH;

    GUARD_PTR(s2n_stuffer_init(&conn->writer_alert_out, &blob));
    GUARD_PTR(s2n_stuffer_alloc(&conn->out, S2N_LARGE_RECORD_LENGTH));

    /* Initialize the growable stuffers. Zero length at first, but the resize
     * in _wipe will fix that 
     */
    blob.data = conn->header_in_data;
    blob.size = S2N_TLS_RECORD_HEADER_LENGTH;

    GUARD_PTR(s2n_stuffer_init(&conn->header_in, &blob));
    GUARD_PTR(s2n_stuffer_growable_alloc(&conn->in, 0));
    GUARD_PTR(s2n_stuffer_growable_alloc(&conn->handshake.io, 0));
    GUARD_PTR(s2n_connection_wipe(conn));
    GUARD_PTR(s2n_timer_start(conn->config, &conn->write_timer));

    return conn;
}

static int s2n_connection_free_keys(struct s2n_connection *conn)
{
    /* Destroy any keys - we call destroy on the object as that is where
     * keys are allocated. */
    if (conn->secure.cipher_suite && conn->secure.cipher_suite->cipher->destroy_key) {
        GUARD(conn->secure.cipher_suite->cipher->destroy_key(&conn->secure.client_key));
        GUARD(conn->secure.cipher_suite->cipher->destroy_key(&conn->secure.server_key));
    }

    /* Free any server key received (we may not have completed a
     * handshake, so this may not have been free'd yet) */
    GUARD(s2n_rsa_public_key_free(&conn->secure.server_rsa_public_key));

    GUARD(s2n_dh_params_free(&conn->secure.server_dh_params));
    GUARD(s2n_ecc_params_free(&conn->secure.server_ecc_params));

    GUARD(s2n_free(&conn->status_response));

    return 0;
}

int s2n_connection_free(struct s2n_connection *conn)
{
    struct s2n_blob blob;

    GUARD(s2n_connection_free_keys(conn));

    GUARD(s2n_stuffer_free(&conn->in));
    GUARD(s2n_stuffer_free(&conn->out));
    GUARD(s2n_stuffer_free(&conn->handshake.io));

    blob.data = (uint8_t *) conn;
    blob.size = sizeof(struct s2n_connection);

    GUARD(s2n_free(&blob));
    return 0;
}

int s2n_connection_set_config(struct s2n_connection *conn, struct s2n_config *config)
{
    conn->config = config;
    return 0;
}

int s2n_connection_wipe(struct s2n_connection *conn)
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
    GUARD(s2n_connection_free_keys(conn));
    GUARD(s2n_stuffer_wipe(&conn->alert_in));
    GUARD(s2n_stuffer_wipe(&conn->reader_alert_out));
    GUARD(s2n_stuffer_wipe(&conn->writer_alert_out));
    GUARD(s2n_stuffer_wipe(&conn->handshake.io));
    GUARD(s2n_stuffer_wipe(&conn->header_in));
    GUARD(s2n_stuffer_wipe(&conn->in));
    GUARD(s2n_stuffer_wipe(&conn->out));

    /* Allocate or resize to their original sizes */
    GUARD(s2n_stuffer_resize(&conn->in, S2N_LARGE_FRAGMENT_LENGTH));

    /* Allocate memory for handling handshakes */
    GUARD(s2n_stuffer_resize(&conn->handshake.io, S2N_LARGE_RECORD_LENGTH));

    /* Clone the stuffers */
    /* ignore gcc 4.7 address warnings because dest is allocated on the stack */
    /* pragma gcc diagnostic was added in gcc 4.6 */
#if defined(__GNUC__) && GCC_VERSION >= 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress"
#endif
    memcpy_check(&alert_in, &conn->alert_in, sizeof(struct s2n_stuffer));
    memcpy_check(&reader_alert_out, &conn->reader_alert_out, sizeof(struct s2n_stuffer));
    memcpy_check(&writer_alert_out, &conn->writer_alert_out, sizeof(struct s2n_stuffer));
    memcpy_check(&handshake_io, &conn->handshake.io, sizeof(struct s2n_stuffer));
    memcpy_check(&header_in, &conn->header_in, sizeof(struct s2n_stuffer));
    memcpy_check(&in, &conn->in, sizeof(struct s2n_stuffer));
    memcpy_check(&out, &conn->out, sizeof(struct s2n_stuffer));
#if defined(__GNUC__) && GCC_VERSION >= 40600
#pragma GCC diagnostic pop
#endif

    /* Zero the whole connection structure */
    memset_check(conn, 0, sizeof(struct s2n_connection));

    conn->readfd = -1;
    conn->writefd = -1;
    conn->mode = mode;
    conn->config = config;
    conn->close_notify_queued = 0;
    conn->current_user_data_consumed = 0;
    conn->initial.cipher_suite = &s2n_null_cipher_suite;
    conn->secure.cipher_suite = &s2n_null_cipher_suite;
    conn->server = &conn->initial;
    conn->client = &conn->initial;
    conn->max_fragment_length = S2N_SMALL_FRAGMENT_LENGTH;
    conn->handshake.handshake_type = 0;
    conn->handshake.message_number = 0;
    GUARD(s2n_hash_init(&conn->handshake.md5, S2N_HASH_MD5));
    GUARD(s2n_hash_init(&conn->handshake.sha1, S2N_HASH_SHA1));
    GUARD(s2n_hash_init(&conn->handshake.sha256, S2N_HASH_SHA256));
    GUARD(s2n_hash_init(&conn->handshake.sha384, S2N_HASH_SHA384));
    GUARD(s2n_hmac_init(&conn->client->client_record_mac, S2N_HMAC_NONE, NULL, 0));
    GUARD(s2n_hmac_init(&conn->server->server_record_mac, S2N_HMAC_NONE, NULL, 0));

    memcpy_check(&conn->alert_in, &alert_in, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->reader_alert_out, &reader_alert_out, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->writer_alert_out, &writer_alert_out, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->handshake.io, &handshake_io, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->header_in, &header_in, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->in, &in, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->out, &out, sizeof(struct s2n_stuffer));

    if (conn->mode == S2N_SERVER) {
        conn->server_protocol_version = s2n_highest_protocol_version;
        conn->client_protocol_version = s2n_unknown_protocol_version;
    }
    else {
        conn->server_protocol_version = s2n_unknown_protocol_version;
        conn->client_protocol_version = s2n_highest_protocol_version;
    }
    conn->actual_protocol_version = s2n_unknown_protocol_version;

    return 0;
}

int s2n_connection_set_read_fd(struct s2n_connection *conn, int rfd)
{
    conn->readfd = rfd;
    return 0;
}

int s2n_connection_set_write_fd(struct s2n_connection *conn, int wfd)
{
    conn->writefd = wfd;
    return 0;
}

int s2n_connection_set_fd(struct s2n_connection *conn, int fd)
{
    GUARD(s2n_connection_set_read_fd(conn, fd));
    GUARD(s2n_connection_set_write_fd(conn, fd));
    return 0;
}

uint64_t s2n_connection_get_wire_bytes_in(struct s2n_connection * conn)
{
    return conn->wire_bytes_in;
}

uint64_t s2n_connection_get_wire_bytes_out(struct s2n_connection * conn)
{
    return conn->wire_bytes_out;
}

const char *s2n_connection_get_cipher(struct s2n_connection *conn)
{
    return conn->secure.cipher_suite->name;
}

int s2n_connection_get_client_protocol_version(struct s2n_connection *conn)
{
    return conn->client_protocol_version;
}

int s2n_connection_get_server_protocol_version(struct s2n_connection *conn)
{
    return conn->server_protocol_version;
}

int s2n_connection_get_actual_protocol_version(struct s2n_connection *conn)
{
    return conn->actual_protocol_version;
}

int s2n_connection_get_client_hello_version(struct s2n_connection *conn)
{
    return conn->client_hello_version;
}

int s2n_connection_get_alert(struct s2n_connection *conn)
{
    if (s2n_stuffer_data_available(&conn->alert_in) != 2) {
        S2N_ERROR(S2N_ERR_NO_ALERT);
    }

    uint8_t alert_code = 0;
    GUARD(s2n_stuffer_read_uint8(&conn->alert_in, &alert_code));
    GUARD(s2n_stuffer_read_uint8(&conn->alert_in, &alert_code));

    return alert_code;
}

int s2n_set_server_name(struct s2n_connection *conn, const char *server_name)
{
    if (conn->mode != S2N_CLIENT) {
        S2N_ERROR(S2N_ERR_CLIENT_MODE);
    }

    int len = strlen(server_name);
    if (len > 255) {
        S2N_ERROR(S2N_ERR_SERVER_NAME_TOO_LONG);
    }

    memcpy_check(conn->server_name, server_name, len);

    return 0;
}

const char *s2n_get_server_name(struct s2n_connection *conn)
{
    if (strlen(conn->server_name) == 0) {
        return NULL;
    }

    return conn->server_name;
}

const char *s2n_get_application_protocol(struct s2n_connection *conn)
{
    if (strlen(conn->application_protocol) == 0) {
        return NULL;
    }

    return conn->application_protocol;
}

int s2n_connection_set_blinding(struct s2n_connection *conn, s2n_blinding blinding)
{
    conn->blinding = blinding;
    return 0;
}

#define ONE_S  INT64_C(1000000000)
#define TEN_S  INT64_C(10000000000)

int64_t s2n_connection_get_delay(struct s2n_connection * conn)
{
    if (!conn->delay) {
        return 0;
    }

    uint64_t elapsed;
    GUARD(s2n_timer_elapsed(conn->config, &conn->write_timer, &elapsed));

    if (elapsed > conn->delay) {
        return 0;
    }

    return conn->delay - elapsed;
}

int s2n_connection_kill(struct s2n_connection *conn)
{
    conn->closed = 1;

    /* Delay between 10 and 30 seconds in nanoseconds */
    int64_t min = TEN_S, max = 3 * TEN_S;

    /* Keep track of the delay so that it can be enforced */
    conn->delay = min + s2n_public_random(max - min);

    /* Restart the write timer */
    GUARD(s2n_timer_start(conn->config, &conn->write_timer));

    if (conn->blinding == S2N_BUILT_IN_BLINDING) {
        struct timespec sleep_time = {.tv_sec = conn->delay / ONE_S,.tv_nsec = conn->delay % ONE_S };
        int r;

        do {
            r = nanosleep(&sleep_time, &sleep_time);
        }
        while (r != 0);
    }

    return 0;
}

const uint8_t *s2n_connection_get_ocsp_response(struct s2n_connection *conn, uint32_t * length)
{
    if (!length) {
        return NULL;
    }

    *length = conn->status_response.size;
    return conn->status_response.data;
}

int s2n_connection_prefer_throughput(struct s2n_connection *conn)
{
    conn->max_fragment_length = S2N_LARGE_FRAGMENT_LENGTH;

    return 0;
}

int s2n_connection_prefer_low_latency(struct s2n_connection *conn)
{
    conn->max_fragment_length = S2N_SMALL_FRAGMENT_LENGTH;

    return 0;
}
