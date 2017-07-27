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

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_cipher.h"

#include "utils/s2n_compiler.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_socket.h"
#include "utils/s2n_timer.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

/* Accept all RSA Certificates is unsafe and is only used in the s2n Client */
int accept_all_rsa_certs(uint8_t *cert_chain_in, uint32_t cert_chain_len, struct s2n_cert_public_key *public_key_out, void *context)
{
    struct s2n_blob cert_chain_blob = { .data = cert_chain_in, .size = cert_chain_len};
    struct s2n_stuffer cert_chain_in_stuffer;
    GUARD(s2n_stuffer_init(&cert_chain_in_stuffer, &cert_chain_blob));
    GUARD(s2n_stuffer_write(&cert_chain_in_stuffer, &cert_chain_blob));

    uint32_t certificate_count = 0;
    while (s2n_stuffer_data_available(&cert_chain_in_stuffer)) {
        uint32_t certificate_size;

        GUARD(s2n_stuffer_read_uint24(&cert_chain_in_stuffer, &certificate_size));

        if (certificate_size == 0 || certificate_size > s2n_stuffer_data_available(&cert_chain_in_stuffer) ) {
            S2N_ERROR(S2N_ERR_BAD_MESSAGE);
        }

        struct s2n_blob asn1cert;
        asn1cert.data = s2n_stuffer_raw_read(&cert_chain_in_stuffer, certificate_size);
        asn1cert.size = certificate_size;
        notnull_check(asn1cert.data);

        /* Pull the public key from the first certificate */
        if (certificate_count == 0) {
            struct s2n_rsa_public_key *rsa_pub_key_out;
            GUARD(s2n_cert_public_key_get_rsa(public_key_out, &rsa_pub_key_out));
            /* Assume that the asn1cert is an RSA Cert */
            GUARD(s2n_asn1der_to_rsa_public_key(rsa_pub_key_out, &asn1cert));
            GUARD(s2n_cert_public_key_set_cert_type(public_key_out, S2N_CERT_TYPE_RSA_SIGN));
        }

        certificate_count++;
    }

    gte_check(certificate_count, 1);
    return 0;
}

struct s2n_connection *s2n_connection_new(s2n_mode mode)
{
    struct s2n_blob blob;
    struct s2n_connection *conn;

    GUARD_PTR(s2n_alloc(&blob, sizeof(struct s2n_connection)));

    GUARD_PTR(s2n_blob_zero(&blob));

    /* Cast 'through' void to acknowledge that we are changing alignment,
     * which is ok, as blob.data is always aligned.
     */
    conn = (struct s2n_connection *)(void *)blob.data;
    conn->config = &s2n_default_config;

    /* By default, only the client will authenticate the Server's Certificate. The Server does not request or
     * authenticate any client certificates. */
    conn->client_cert_auth_type = conn->config->client_cert_auth_type;
    conn->verify_cert_chain_cb = conn->config->verify_cert_chain_cb;
    conn->verify_cert_context = conn->config->verify_cert_context;

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

        conn->verify_cert_chain_cb = accept_all_rsa_certs;
    }

    conn->mode = mode;
    conn->blinding = S2N_BUILT_IN_BLINDING;
    conn->close_notify_queued = 0;
    conn->session_id_len = 0;
    conn->send = NULL;
    conn->recv = NULL;
    conn->send_io_context = NULL;
    conn->recv_io_context = NULL;
    conn->managed_io = 0;
    conn->corked_io = 0;
    conn->context = NULL;

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

    /* Allocate long term key memory */
    GUARD_PTR(s2n_session_key_alloc(&conn->secure.client_key));
    GUARD_PTR(s2n_session_key_alloc(&conn->secure.server_key));
    GUARD_PTR(s2n_session_key_alloc(&conn->initial.client_key));
    GUARD_PTR(s2n_session_key_alloc(&conn->initial.server_key));

    GUARD_PTR(s2n_prf_new(conn));

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
    GUARD(s2n_session_key_free(&conn->secure.client_key));
    GUARD(s2n_session_key_free(&conn->secure.server_key));
    GUARD(s2n_session_key_free(&conn->initial.client_key));
    GUARD(s2n_session_key_free(&conn->initial.server_key));

    return 0;
}

static int s2n_connection_zero(struct s2n_connection *conn, int mode, struct s2n_config *config)
{
    /* Preserve the PRF state before zeroing the connection struct */
    struct s2n_evp_hmac_state p_hash_evp_hmac = conn->prf_space.tls.p_hash.evp_hmac;
    const struct s2n_p_hash_hmac *p_hash_hmac = conn->prf_space.tls.p_hash_hmac;

    /* Zero the whole connection structure */
    memset_check(conn, 0, sizeof(struct s2n_connection));

    conn->send = NULL;
    conn->recv = NULL;
    conn->send_io_context = NULL;
    conn->recv_io_context = NULL;
    conn->mode = mode;
    conn->config = config;
    conn->prf_space.tls.p_hash.evp_hmac = p_hash_evp_hmac;
    conn->prf_space.tls.p_hash_hmac = p_hash_hmac;
    conn->close_notify_queued = 0;
    conn->current_user_data_consumed = 0;
    conn->initial.cipher_suite = &s2n_null_cipher_suite;
    conn->secure.cipher_suite = &s2n_null_cipher_suite;
    conn->server = &conn->initial;
    conn->client = &conn->initial;
    conn->max_outgoing_fragment_length = S2N_DEFAULT_FRAGMENT_LENGTH;
    conn->handshake.handshake_type = INITIAL;
    conn->handshake.message_number = 0;
    conn->client_cert_auth_type = S2N_CERT_AUTH_NONE;
    conn->verify_cert_chain_cb = deny_all_certs;
    conn->verify_cert_context = NULL;
    GUARD(s2n_hash_init(&conn->handshake.md5, S2N_HASH_MD5));
    GUARD(s2n_hash_init(&conn->handshake.sha1, S2N_HASH_SHA1));
    GUARD(s2n_hash_init(&conn->handshake.sha224, S2N_HASH_SHA224));
    GUARD(s2n_hash_init(&conn->handshake.sha256, S2N_HASH_SHA256));
    GUARD(s2n_hash_init(&conn->handshake.sha384, S2N_HASH_SHA384));
    GUARD(s2n_hash_init(&conn->handshake.sha512, S2N_HASH_SHA512));
    GUARD(s2n_hmac_init(&conn->client->client_record_mac, S2N_HMAC_NONE, NULL, 0));
    GUARD(s2n_hmac_init(&conn->server->server_record_mac, S2N_HMAC_NONE, NULL, 0));

    return 0;
}

static int s2n_connection_wipe_keys(struct s2n_connection *conn)
{
    /* Destroy any keys - we call destroy on the object as that is where
     * keys are allocated. */
    if (conn->secure.cipher_suite && conn->secure.cipher_suite->record_alg->cipher->destroy_key) {
        GUARD(conn->secure.cipher_suite->record_alg->cipher->destroy_key(&conn->secure.client_key));
        GUARD(conn->secure.cipher_suite->record_alg->cipher->destroy_key(&conn->secure.server_key));
    }

    /* Free any server key received (we may not have completed a
     * handshake, so this may not have been free'd yet) */
    GUARD(s2n_rsa_public_key_free(&conn->secure.server_rsa_public_key));
    GUARD(s2n_rsa_public_key_free(&conn->secure.client_rsa_public_key));

    GUARD(s2n_dh_params_free(&conn->secure.server_dh_params));
    GUARD(s2n_ecc_params_free(&conn->secure.server_ecc_params));
    GUARD(s2n_free(&conn->secure.client_cert_chain));
    GUARD(s2n_free(&conn->ct_response));

    return 0;
}

static int s2n_connection_free_io_contexts(struct s2n_connection *conn)
{
    /* Free the I/O context if it was allocated by s2n. Don't touch user-controlled contexts. */
    if (!conn->managed_io) {
        return 0;
    }

    struct s2n_blob send_io_blob;
    struct s2n_blob recv_io_blob;

    if (conn->send_io_context) {
        send_io_blob.data = (uint8_t *)conn->send_io_context;
        send_io_blob.size = sizeof(struct s2n_socket_write_io_context);
        GUARD(s2n_free(&send_io_blob));
    }

    if (conn->recv_io_context) {
        recv_io_blob.data = (uint8_t *)conn->recv_io_context;
        recv_io_blob.size = sizeof(struct s2n_socket_read_io_context);
        GUARD(s2n_free(&recv_io_blob));
    }

    return 0;
}

static int s2n_connection_wipe_io(struct s2n_connection *conn)
{
    if (s2n_connection_is_managed_corked(conn) && conn->recv){
        GUARD(s2n_socket_read_restore(conn));
    }
    if (s2n_connection_is_managed_corked(conn) && conn->send){
        GUARD(s2n_socket_write_restore(conn));
    }

    /* Remove all I/O-related members */
    GUARD(s2n_connection_free_io_contexts(conn));
    conn->managed_io = 0;
    conn->send = NULL;
    conn->recv = NULL;

    return 0;
}

int s2n_connection_free(struct s2n_connection *conn)
{
    struct s2n_blob blob;

    GUARD(s2n_connection_wipe_keys(conn));
    GUARD(s2n_connection_free_keys(conn));

    GUARD(s2n_prf_free(conn));

    GUARD(s2n_free(&conn->status_response));
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

int s2n_connection_set_ctx(struct s2n_connection *conn, void *ctx)
{
    conn->context = ctx;
    return 0;
}

void *s2n_connection_get_ctx(struct s2n_connection *conn)
{
    return conn->context;
}

int s2n_connection_wipe(struct s2n_connection *conn)
{
    /* First make a copy of everything we'd like to save, which isn't very much. */
    int mode = conn->mode;
    struct s2n_config *config = conn->config;
    struct s2n_stuffer alert_in;
    struct s2n_stuffer reader_alert_out;
    struct s2n_stuffer writer_alert_out;
    struct s2n_stuffer handshake_io;
    struct s2n_stuffer header_in;
    struct s2n_stuffer in;
    struct s2n_stuffer out;
    /* Session keys will be wiped. Preserve structs to avoid reallocation */
    struct s2n_session_key initial_client_key;
    struct s2n_session_key initial_server_key;
    struct s2n_session_key secure_client_key;
    struct s2n_session_key secure_server_key;

    /* Wipe all of the sensitive stuff */
    GUARD(s2n_connection_wipe_keys(conn));
    GUARD(s2n_stuffer_wipe(&conn->alert_in));
    GUARD(s2n_stuffer_wipe(&conn->reader_alert_out));
    GUARD(s2n_stuffer_wipe(&conn->writer_alert_out));
    GUARD(s2n_stuffer_wipe(&conn->handshake.io));
    GUARD(s2n_stuffer_wipe(&conn->header_in));
    GUARD(s2n_stuffer_wipe(&conn->in));
    GUARD(s2n_stuffer_wipe(&conn->out));

    /* Wipe the I/O-related info and restore the original socket if necessary */
    GUARD(s2n_connection_wipe_io(conn));

    GUARD(s2n_free(&conn->status_response));

    /* Allocate or resize to their original sizes */
    GUARD(s2n_stuffer_resize(&conn->in, S2N_LARGE_FRAGMENT_LENGTH));

    /* Allocate memory for handling handshakes */
    GUARD(s2n_stuffer_resize(&conn->handshake.io, S2N_LARGE_RECORD_LENGTH));

    /* Remove context associated with connection */
    conn->context = NULL;

    /* Clone the stuffers */
    /* ignore gcc 4.7 address warnings because dest is allocated on the stack */
    /* pragma gcc diagnostic was added in gcc 4.6 */
#if S2N_GCC_VERSION_AT_LEAST(4,6,0)
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
    memcpy_check(&initial_client_key, &conn->initial.client_key, sizeof(struct s2n_session_key));
    memcpy_check(&initial_server_key, &conn->initial.server_key, sizeof(struct s2n_session_key));
    memcpy_check(&secure_client_key, &conn->secure.client_key, sizeof(struct s2n_session_key));
    memcpy_check(&secure_server_key, &conn->secure.server_key, sizeof(struct s2n_session_key));
#if S2N_GCC_VERSION_AT_LEAST(4,6,0)
#pragma GCC diagnostic pop
#endif

    GUARD(s2n_connection_zero(conn, mode, config));

    memcpy_check(&conn->alert_in, &alert_in, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->reader_alert_out, &reader_alert_out, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->writer_alert_out, &writer_alert_out, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->handshake.io, &handshake_io, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->header_in, &header_in, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->in, &in, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->out, &out, sizeof(struct s2n_stuffer));
    memcpy_check(&conn->initial.client_key, &initial_client_key, sizeof(struct s2n_session_key));
    memcpy_check(&conn->initial.server_key, &initial_server_key, sizeof(struct s2n_session_key));
    memcpy_check(&conn->secure.client_key, &secure_client_key, sizeof(struct s2n_session_key));
    memcpy_check(&conn->secure.server_key, &secure_server_key, sizeof(struct s2n_session_key));

    if (conn->mode == S2N_SERVER) {
        /* Start with the highest protocol version so that the highest common protocol version can be selected */
        /* during handshake. */
        conn->server_protocol_version = s2n_highest_protocol_version;
        conn->client_protocol_version = s2n_unknown_protocol_version;
        conn->actual_protocol_version = s2n_unknown_protocol_version;
    }
    else {
        /* For clients, also set actual_protocol_version.  Record generation uses that value for the initial */
        /* ClientHello record version. Not all servers ignore the record version in ClientHello. */
        conn->verify_cert_chain_cb = accept_all_rsa_certs;
        conn->server_protocol_version = s2n_unknown_protocol_version;
        conn->client_protocol_version = s2n_highest_protocol_version;
        conn->actual_protocol_version = s2n_highest_protocol_version;
    }

    return 0;
}

int s2n_connection_set_recv_ctx(struct s2n_connection *conn, void *ctx)
{
    conn->recv_io_context = ctx;
    return 0;
}

int s2n_connection_set_send_ctx(struct s2n_connection *conn, void *ctx)
{
    conn->send_io_context = ctx;
    return 0;
}

int s2n_connection_set_recv_cb(struct s2n_connection *conn, s2n_recv_fn recv)
{
    conn->recv = recv;
    return 0;
}

int s2n_connection_set_send_cb(struct s2n_connection *conn, s2n_send_fn send)
{
    conn->send = send;
    return 0;
}

int s2n_connection_set_cert_auth_type(struct s2n_connection *conn, s2n_cert_auth_type cert_auth_type)
{
    conn->client_cert_auth_type = cert_auth_type;
    return 0;
}

int s2n_connection_set_verify_cert_chain_cb(struct s2n_connection *conn, verify_cert_trust_chain *callback, void *context)
{
    notnull_check(callback);
    conn->verify_cert_chain_cb = callback;
    conn->verify_cert_context = context;
    return 0;
}

int s2n_connection_set_read_fd(struct s2n_connection *conn, int rfd)
{
    struct s2n_blob ctx_mem;
    struct s2n_socket_read_io_context *peer_socket_ctx;

    GUARD(s2n_alloc(&ctx_mem, sizeof(struct s2n_socket_read_io_context)));

    peer_socket_ctx = (struct s2n_socket_read_io_context *)(void *)ctx_mem.data;
    peer_socket_ctx->fd = rfd;

    s2n_connection_set_recv_cb(conn, s2n_socket_read);
    s2n_connection_set_recv_ctx(conn, peer_socket_ctx);
    conn->managed_io = 1;

    /* This is only needed if the user is using corked io.
     * Take the snapshot in case optimized io is enabled after setting the fd.
     */
    GUARD(s2n_socket_read_snapshot(conn));

    return 0;
}

int s2n_connection_set_write_fd(struct s2n_connection *conn, int wfd)
{
    struct s2n_blob ctx_mem;
    struct s2n_socket_write_io_context *peer_socket_ctx;

    GUARD(s2n_alloc(&ctx_mem, sizeof(struct s2n_socket_write_io_context)));

    peer_socket_ctx = (struct s2n_socket_write_io_context *)(void *)ctx_mem.data;
    peer_socket_ctx->fd = wfd;

    s2n_connection_set_send_cb(conn, s2n_socket_write);
    s2n_connection_set_send_ctx(conn, peer_socket_ctx);
    conn->managed_io = 1;

    /* This is only needed if the user is using corked io.
     * Take the snapshot in case optimized io is enabled after setting the fd.
     */
    GUARD(s2n_socket_write_snapshot(conn));

    return 0;
}

int s2n_connection_set_fd(struct s2n_connection *conn, int fd)
{
    GUARD(s2n_connection_set_read_fd(conn, fd));
    GUARD(s2n_connection_set_write_fd(conn, fd));
    return 0;
}

int s2n_connection_use_corked_io(struct s2n_connection *conn)
{
    if (!conn->managed_io) {
        /* Caller shouldn't be trying to set s2n IO corked on non-s2n-managed IO */
        S2N_ERROR(S2N_ERR_CORK_SET_ON_UNMANAGED);
    }
    conn->corked_io = 1;

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

const char *s2n_connection_get_curve(struct s2n_connection *conn)
{
    if (!conn->secure.server_ecc_params.negotiated_curve) {
        return "NONE";
    }

    return conn->secure.server_ecc_params.negotiated_curve->name;
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

uint64_t s2n_connection_get_delay(struct s2n_connection * conn)
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
    conn->max_outgoing_fragment_length = S2N_LARGE_FRAGMENT_LENGTH;

    return 0;
}

int s2n_connection_prefer_low_latency(struct s2n_connection *conn)
{
    conn->max_outgoing_fragment_length = S2N_SMALL_FRAGMENT_LENGTH;

    return 0;
}

int s2n_connection_recv_stuffer(struct s2n_stuffer *stuffer, struct s2n_connection *conn, uint32_t len)
{
    notnull_check(conn->recv);
    /* Make sure we have enough space to write */
    GUARD(s2n_stuffer_skip_write(stuffer, len));

    /* "undo" the skip write */
    stuffer->write_cursor -= len;

  RECV:
    errno = 0;
    int r = conn->recv(conn->recv_io_context, stuffer->blob.data + stuffer->write_cursor, len);
    if (r < 0) {
        if (errno == EINTR) {
            goto RECV;
        }
        return -1;
    }

    /* Record just how many bytes we have written */
    stuffer->write_cursor += r;
    stuffer->wiped = 0;

    return r;
}

int s2n_connection_send_stuffer(struct s2n_stuffer *stuffer, struct s2n_connection *conn, uint32_t len)
{
    notnull_check(conn->send);
    /* Make sure we even have the data */
    GUARD(s2n_stuffer_skip_read(stuffer, len));

    /* "undo" the skip read */
    stuffer->read_cursor -= len;

  SEND:
    errno = 0;
    int w = conn->send(conn->send_io_context, stuffer->blob.data + stuffer->read_cursor, len);
    if(w < 0) {
        if (errno == EINTR) {
            goto SEND;
        }
        return -1;
    }

    stuffer->read_cursor += w;

    return w;
}

int s2n_connection_is_managed_corked(const struct s2n_connection *s2n_connection)
{
    return (s2n_connection->managed_io && s2n_connection->corked_io);
}

const uint8_t *s2n_connection_get_sct_list(struct s2n_connection *conn, uint32_t *length)
{
    if (!length) {
        return NULL;
    }

    *length = conn->ct_response.size;
    return conn->ct_response.data;
}
