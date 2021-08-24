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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/param.h>

#include <s2n.h>
#include <stdbool.h>

#include "crypto/s2n_fips.h"

#include "error/s2n_errno.h"

#include "tls/extensions/s2n_client_server_name.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_connection_evp_digests.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_prf.h"
#include "tls/s2n_record.h"
#include "tls/s2n_resume.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_cipher.h"
#include "crypto/s2n_crypto.h"
#include "crypto/s2n_openssl_x509.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_compiler.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_socket.h"
#include "utils/s2n_timer.h"

#define S2N_SET_KEY_SHARE_LIST_EMPTY(keyshares) (keyshares |= 1)
#define S2N_SET_KEY_SHARE_REQUEST(keyshares, i) (keyshares |= ( 1 << ( i + 1 )))

static int s2n_connection_new_hmacs(struct s2n_connection *conn)
{
    /* Allocate long-term memory for the Connection's HMAC states */
    POSIX_GUARD(s2n_hmac_new(&conn->initial.client_record_mac));
    POSIX_GUARD(s2n_hmac_new(&conn->initial.server_record_mac));
    POSIX_GUARD(s2n_hmac_new(&conn->secure.client_record_mac));
    POSIX_GUARD(s2n_hmac_new(&conn->secure.server_record_mac));

    return 0;
}

static int s2n_connection_init_hmacs(struct s2n_connection *conn)
{
    /* Initialize all of the Connection's HMAC states */
    POSIX_GUARD(s2n_hmac_init(&conn->initial.client_record_mac, S2N_HMAC_NONE, NULL, 0));
    POSIX_GUARD(s2n_hmac_init(&conn->initial.server_record_mac, S2N_HMAC_NONE, NULL, 0));
    POSIX_GUARD(s2n_hmac_init(&conn->secure.client_record_mac, S2N_HMAC_NONE, NULL, 0));
    POSIX_GUARD(s2n_hmac_init(&conn->secure.server_record_mac, S2N_HMAC_NONE, NULL, 0));

    return 0;
}

struct s2n_connection *s2n_connection_new(s2n_mode mode)
{
    struct s2n_blob blob = {0};
    PTR_GUARD_POSIX(s2n_alloc(&blob, sizeof(struct s2n_connection)));
    PTR_GUARD_POSIX(s2n_blob_zero(&blob));

    /* Cast 'through' void to acknowledge that we are changing alignment,
     * which is ok, as blob.data is always aligned.
     */
    struct s2n_connection* conn = (struct s2n_connection *)(void *)blob.data;

    PTR_GUARD_POSIX(s2n_connection_set_config(conn, s2n_fetch_default_config()));

    conn->mode = mode;
    conn->blinding = S2N_BUILT_IN_BLINDING;
    conn->close_notify_queued = 0;
    conn->client_session_resumed = 0;
    conn->session_id_len = 0;
    conn->verify_host_fn = NULL;
    conn->data_for_verify_host = NULL;
    conn->verify_host_fn_overridden = 0;
    conn->data_for_verify_host = NULL;
    conn->send = NULL;
    conn->recv = NULL;
    conn->send_io_context = NULL;
    conn->recv_io_context = NULL;
    conn->managed_io = 0;
    conn->corked_io = 0;
    conn->context = NULL;
    conn->security_policy_override = NULL;
    conn->ticket_lifetime_hint = 0;
    conn->session_ticket_status = S2N_NO_TICKET;

    /* Allocate the fixed-size stuffers */
    blob = (struct s2n_blob) {0};
    PTR_GUARD_POSIX(s2n_blob_init(&blob, conn->alert_in_data, S2N_ALERT_LENGTH));
    PTR_GUARD_POSIX(s2n_stuffer_init(&conn->alert_in, &blob));

    blob = (struct s2n_blob) {0};
    PTR_GUARD_POSIX(s2n_blob_init(&blob, conn->reader_alert_out_data, S2N_ALERT_LENGTH));
    PTR_GUARD_POSIX(s2n_stuffer_init(&conn->reader_alert_out, &blob));

    blob = (struct s2n_blob) {0};
    PTR_GUARD_POSIX(s2n_blob_init(&blob, conn->writer_alert_out_data, S2N_ALERT_LENGTH));
    PTR_GUARD_POSIX(s2n_stuffer_init(&conn->writer_alert_out, &blob));

    blob = (struct s2n_blob) {0};
    PTR_GUARD_POSIX(s2n_blob_init(&blob, conn->ticket_ext_data, S2N_TLS12_TICKET_SIZE_IN_BYTES));
    PTR_GUARD_POSIX(s2n_stuffer_init(&conn->client_ticket_to_decrypt, &blob));

    /* Allocate long term key memory */
    PTR_GUARD_POSIX(s2n_session_key_alloc(&conn->secure.client_key));
    PTR_GUARD_POSIX(s2n_session_key_alloc(&conn->secure.server_key));
    PTR_GUARD_POSIX(s2n_session_key_alloc(&conn->initial.client_key));
    PTR_GUARD_POSIX(s2n_session_key_alloc(&conn->initial.server_key));

    /* Allocate long term hash and HMAC memory */
    PTR_GUARD_RESULT(s2n_prf_new(conn));
    PTR_GUARD_RESULT(s2n_handshake_hashes_new(&conn->handshake.hashes));

    PTR_GUARD_POSIX(s2n_connection_new_hmacs(conn));
    PTR_GUARD_POSIX(s2n_connection_init_hmacs(conn));

    /* Initialize the growable stuffers. Zero length at first, but the resize
     * in _wipe will fix that
     */
    blob = (struct s2n_blob) {0};
    PTR_GUARD_POSIX(s2n_blob_init(&blob, conn->header_in_data, S2N_TLS_RECORD_HEADER_LENGTH));
    PTR_GUARD_POSIX(s2n_stuffer_init(&conn->header_in, &blob));
    PTR_GUARD_POSIX(s2n_stuffer_growable_alloc(&conn->out, 0));
    PTR_GUARD_POSIX(s2n_stuffer_growable_alloc(&conn->in, 0));
    PTR_GUARD_POSIX(s2n_stuffer_growable_alloc(&conn->handshake.io, 0));
    PTR_GUARD_POSIX(s2n_stuffer_growable_alloc(&conn->client_hello.raw_message, 0));
    PTR_GUARD_POSIX(s2n_connection_wipe(conn));
    PTR_GUARD_RESULT(s2n_timer_start(conn->config, &conn->write_timer));

    /* Initialize the cookie stuffer with zero length. If a cookie extension
     * is received, the stuffer will be resized according to the cookie length */
    PTR_GUARD_POSIX(s2n_stuffer_growable_alloc(&conn->cookie_stuffer, 0));

    return conn;
}

static int s2n_connection_free_keys(struct s2n_connection *conn)
{
    POSIX_GUARD(s2n_session_key_free(&conn->secure.client_key));
    POSIX_GUARD(s2n_session_key_free(&conn->secure.server_key));
    POSIX_GUARD(s2n_session_key_free(&conn->initial.client_key));
    POSIX_GUARD(s2n_session_key_free(&conn->initial.server_key));

    return 0;
}

static int s2n_connection_zero(struct s2n_connection *conn, int mode, struct s2n_config *config)
{
    /* Zero the whole connection structure */
    POSIX_CHECKED_MEMSET(conn, 0, sizeof(struct s2n_connection));

    conn->mode = mode;
    conn->initial.cipher_suite = &s2n_null_cipher_suite;
    conn->secure.cipher_suite = &s2n_null_cipher_suite;
    conn->server = &conn->initial;
    conn->client = &conn->initial;
    conn->max_outgoing_fragment_length = S2N_DEFAULT_FRAGMENT_LENGTH;
    conn->handshake.end_of_messages = APPLICATION_DATA;
    s2n_connection_set_config(conn, config);

    return 0;
}

S2N_RESULT s2n_connection_wipe_all_keyshares(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);

    RESULT_GUARD_POSIX(s2n_ecc_evp_params_free(&conn->kex_params.server_ecc_evp_params));
    RESULT_GUARD_POSIX(s2n_ecc_evp_params_free(&conn->kex_params.client_ecc_evp_params));

    RESULT_GUARD_POSIX(s2n_kem_group_free(&conn->kex_params.server_kem_group_params));
    RESULT_GUARD_POSIX(s2n_kem_group_free(&conn->kex_params.client_kem_group_params));

    return S2N_RESULT_OK;
}

static int s2n_connection_wipe_keys(struct s2n_connection *conn)
{
    /* Destroy any keys - we call destroy on the object as that is where
     * keys are allocated. */
    if (conn->secure.cipher_suite
            && conn->secure.cipher_suite->record_alg
            && conn->secure.cipher_suite->record_alg->cipher
            && conn->secure.cipher_suite->record_alg->cipher->destroy_key) {
        POSIX_GUARD(conn->secure.cipher_suite->record_alg->cipher->destroy_key(&conn->secure.client_key));
        POSIX_GUARD(conn->secure.cipher_suite->record_alg->cipher->destroy_key(&conn->secure.server_key));
    }

    /* Free any server key received (we may not have completed a
     * handshake, so this may not have been free'd yet) */
    POSIX_GUARD(s2n_pkey_free(&conn->handshake_params.server_public_key));
    POSIX_GUARD(s2n_pkey_zero_init(&conn->handshake_params.server_public_key));
    POSIX_GUARD(s2n_pkey_free(&conn->handshake_params.client_public_key));
    POSIX_GUARD(s2n_pkey_zero_init(&conn->handshake_params.client_public_key));
    s2n_x509_validator_wipe(&conn->x509_validator);
    POSIX_GUARD(s2n_dh_params_free(&conn->kex_params.server_dh_params));
    POSIX_GUARD_RESULT(s2n_connection_wipe_all_keyshares(conn));
    POSIX_GUARD(s2n_kem_free(&conn->kex_params.kem_params));
    POSIX_GUARD(s2n_free(&conn->handshake_params.client_cert_chain));
    POSIX_GUARD(s2n_free(&conn->ct_response));

    return 0;
}

static int s2n_connection_reset_hmacs(struct s2n_connection *conn)
{
    /* Reset all of the Connection's HMAC states */
    POSIX_GUARD(s2n_hmac_reset(&conn->initial.client_record_mac));
    POSIX_GUARD(s2n_hmac_reset(&conn->initial.server_record_mac));
    POSIX_GUARD(s2n_hmac_reset(&conn->secure.client_record_mac));
    POSIX_GUARD(s2n_hmac_reset(&conn->secure.server_record_mac));

    return 0;
}

static int s2n_connection_free_io_contexts(struct s2n_connection *conn)
{
    /* Free the I/O context if it was allocated by s2n. Don't touch user-controlled contexts. */
    if (!conn->managed_io) {
        return 0;
    }

    POSIX_GUARD(s2n_free_object((uint8_t **)&conn->send_io_context, sizeof(struct s2n_socket_write_io_context)));
    POSIX_GUARD(s2n_free_object((uint8_t **)&conn->recv_io_context, sizeof(struct s2n_socket_read_io_context)));

    return 0;
}

static int s2n_connection_wipe_io(struct s2n_connection *conn)
{
    if (s2n_connection_is_managed_corked(conn) && conn->recv){
        POSIX_GUARD(s2n_socket_read_restore(conn));
    }
    if (s2n_connection_is_managed_corked(conn) && conn->send){
        POSIX_GUARD(s2n_socket_write_restore(conn));
    }

    /* Remove all I/O-related members */
    POSIX_GUARD(s2n_connection_free_io_contexts(conn));
    conn->managed_io = 0;
    conn->send = NULL;
    conn->recv = NULL;

    return 0;
}

static int s2n_connection_free_hmacs(struct s2n_connection *conn)
{
    /* Free all of the Connection's HMAC states */
    POSIX_GUARD(s2n_hmac_free(&conn->initial.client_record_mac));
    POSIX_GUARD(s2n_hmac_free(&conn->initial.server_record_mac));
    POSIX_GUARD(s2n_hmac_free(&conn->secure.client_record_mac));
    POSIX_GUARD(s2n_hmac_free(&conn->secure.server_record_mac));

    return 0;
}

static uint8_t s2n_default_verify_host(const char *host_name, size_t len, void *data)
{
    /* if present, match server_name of the connection using rules
     * outlined in RFC6125 6.4. */

    struct s2n_connection *conn = data;

    if (conn->server_name[0] == '\0') {
        return 0;
    }

    /* complete match */
    if (strlen(conn->server_name) == len &&
            strncasecmp(conn->server_name, host_name, len) == 0) {
        return 1;
    }

    /* match 1 level of wildcard */
    if (len > 2 && host_name[0] == '*' && host_name[1] == '.') {
        const char *suffix = strchr(conn->server_name, '.');

        if (suffix == NULL) {
            return 0;
        }

        if (strlen(suffix) == len - 1 &&
                strncasecmp(suffix, host_name + 1, len - 1) == 0) {
            return 1;
        }
    }

    return 0;
}

int s2n_connection_free(struct s2n_connection *conn)
{
    POSIX_GUARD(s2n_connection_wipe_keys(conn));
    POSIX_GUARD(s2n_connection_free_keys(conn));
    POSIX_GUARD_RESULT(s2n_psk_parameters_wipe(&conn->psk_params));

    POSIX_GUARD_RESULT(s2n_prf_free(conn));
    POSIX_GUARD_RESULT(s2n_handshake_hashes_free(&conn->handshake.hashes));

    POSIX_GUARD(s2n_connection_reset_hmacs(conn));
    POSIX_GUARD(s2n_connection_free_hmacs(conn));

    POSIX_GUARD(s2n_connection_free_io_contexts(conn));

    POSIX_GUARD(s2n_free(&conn->client_ticket));
    POSIX_GUARD(s2n_free(&conn->status_response));
    POSIX_GUARD(s2n_free(&conn->our_quic_transport_parameters));
    POSIX_GUARD(s2n_free(&conn->peer_quic_transport_parameters));
    POSIX_GUARD(s2n_free(&conn->server_early_data_context));
    POSIX_GUARD(s2n_free(&conn->tls13_ticket_fields.session_secret));
    POSIX_GUARD(s2n_stuffer_free(&conn->in));
    POSIX_GUARD(s2n_stuffer_free(&conn->out));
    POSIX_GUARD(s2n_stuffer_free(&conn->handshake.io));
    s2n_x509_validator_wipe(&conn->x509_validator);
    POSIX_GUARD(s2n_client_hello_free(&conn->client_hello));
    POSIX_GUARD(s2n_free(&conn->application_protocols_overridden));
    POSIX_GUARD(s2n_stuffer_free(&conn->cookie_stuffer));
    POSIX_GUARD(s2n_free_object((uint8_t **)&conn, sizeof(struct s2n_connection)));

    return 0;
}

int s2n_connection_set_config(struct s2n_connection *conn, struct s2n_config *config)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(config);

    if (conn->config == config) {
        return 0;
    }

    /* We only support one client certificate */
    if (s2n_config_get_num_default_certs(config) > 1 && conn->mode == S2N_CLIENT) {
        POSIX_BAIL(S2N_ERR_TOO_MANY_CERTIFICATES);
    }

    s2n_x509_validator_wipe(&conn->x509_validator);

    s2n_cert_auth_type auth_type = config->client_cert_auth_type;

    if (conn->client_cert_auth_type_overridden) {
        auth_type = conn->client_cert_auth_type;
    }

    int8_t dont_need_x509_validation = (conn->mode == S2N_SERVER) && (auth_type == S2N_CERT_AUTH_NONE);

    if (config->disable_x509_validation || dont_need_x509_validation) {
        POSIX_GUARD(s2n_x509_validator_init_no_x509_validation(&conn->x509_validator));
    }
    else {
        POSIX_GUARD(s2n_x509_validator_init(&conn->x509_validator, &config->trust_store, config->check_ocsp));
        if (!conn->verify_host_fn_overridden) {
            if (config->verify_host != NULL) {
                conn->verify_host_fn = config->verify_host;
                conn->data_for_verify_host = config->data_for_verify_host;
            } else {
                conn->verify_host_fn = s2n_default_verify_host;
                conn->data_for_verify_host = conn;
            }
        }

        if (config->max_verify_cert_chain_depth_set) {
            POSIX_GUARD(s2n_x509_validator_set_max_chain_depth(&conn->x509_validator, config->max_verify_cert_chain_depth));
        }
    }
    conn->tickets_to_send = config->initial_tickets_to_send;

    if (conn->psk_params.psk_list.len == 0 && !conn->psk_mode_overridden) {
        POSIX_GUARD(s2n_connection_set_psk_mode(conn, config->psk_mode));
        conn->psk_mode_overridden = false;
    }

    /* If at least one certificate does not have a private key configured,
     * the config must provide an async pkey callback.
     * The handshake could still fail if the callback doesn't offload the
     * signature, but this is at least catches most mistakes.
     */
    if (!config->async_pkey_cb) {
        POSIX_ENSURE(!config->no_signing_key, S2N_ERR_NO_PRIVATE_KEY);
    }

    conn->config = config;
    return S2N_SUCCESS;
}

int s2n_connection_server_name_extension_used(struct s2n_connection *conn)
{

    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE(conn->mode == S2N_SERVER, S2N_ERR_INVALID_STATE);
    POSIX_ENSURE(!(conn->handshake.client_hello_received), S2N_ERR_INVALID_STATE);

    conn->server_name_used = 1;
    return S2N_SUCCESS;
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

int s2n_connection_release_buffers(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_PRECONDITION(s2n_stuffer_validate(&conn->out));
    POSIX_PRECONDITION(s2n_stuffer_validate(&conn->in));

    POSIX_ENSURE(s2n_stuffer_is_consumed(&conn->out), S2N_ERR_STUFFER_HAS_UNPROCESSED_DATA);
    POSIX_GUARD(s2n_stuffer_resize(&conn->out, 0));

    POSIX_ENSURE(s2n_stuffer_is_consumed(&conn->in), S2N_ERR_STUFFER_HAS_UNPROCESSED_DATA);
    POSIX_GUARD(s2n_stuffer_resize(&conn->in, 0));

    POSIX_POSTCONDITION(s2n_stuffer_validate(&conn->out));
    POSIX_POSTCONDITION(s2n_stuffer_validate(&conn->in));
    return S2N_SUCCESS;
}

int s2n_connection_free_handshake(struct s2n_connection *conn)
{
    /* We are done with the handshake */
    POSIX_GUARD_RESULT(s2n_handshake_hashes_free(&conn->handshake.hashes));
    POSIX_GUARD_RESULT(s2n_prf_free(conn));

    /* Wipe the buffers we are going to free */
    POSIX_GUARD(s2n_stuffer_wipe(&conn->handshake.io));
    POSIX_GUARD(s2n_stuffer_wipe(&conn->client_hello.raw_message));

    /* Truncate buffers to save memory, we are done with the handshake */
    POSIX_GUARD(s2n_stuffer_resize(&conn->handshake.io, 0));
    POSIX_GUARD(s2n_stuffer_resize(&conn->client_hello.raw_message, 0));

    /* We can free extension data we no longer need */
    POSIX_GUARD(s2n_free(&conn->client_ticket));
    POSIX_GUARD(s2n_free(&conn->status_response));
    POSIX_GUARD(s2n_free(&conn->our_quic_transport_parameters));
    POSIX_GUARD(s2n_free(&conn->application_protocols_overridden));
    POSIX_GUARD(s2n_stuffer_free(&conn->cookie_stuffer));

    return 0;
}

int s2n_connection_wipe(struct s2n_connection *conn)
{
    /* First make a copy of everything we'd like to save, which isn't very much. */
    int mode = conn->mode;
    struct s2n_config *config = conn->config;
    struct s2n_stuffer alert_in = {0};
    struct s2n_stuffer reader_alert_out = {0};
    struct s2n_stuffer writer_alert_out = {0};
    struct s2n_stuffer client_ticket_to_decrypt = {0};
    struct s2n_stuffer handshake_io = {0};
    struct s2n_stuffer client_hello_raw_message = {0};
    struct s2n_stuffer header_in = {0};
    struct s2n_stuffer in = {0};
    struct s2n_stuffer out = {0};
    /* Session keys will be wiped. Preserve structs to avoid reallocation */
    struct s2n_session_key initial_client_key = {0};
    struct s2n_session_key initial_server_key = {0};
    struct s2n_session_key secure_client_key = {0};
    struct s2n_session_key secure_server_key = {0};
    /* Parts of the hmac states will be wiped. Preserve structs to avoid reallocation */
    struct s2n_connection_hmac_handles hmac_handles = {0};

    /* Some required structures might have been freed to conserve memory between handshakes.
     * Restore them.
     */

    if (!conn->handshake.hashes) {
        POSIX_GUARD_RESULT(s2n_handshake_hashes_new(&conn->handshake.hashes));
    }
    POSIX_GUARD_RESULT(s2n_handshake_hashes_wipe(conn->handshake.hashes));
    struct s2n_handshake_hashes *handshake_hashes = conn->handshake.hashes;

    if (!conn->prf_space) {
        POSIX_GUARD_RESULT(s2n_prf_new(conn));
    }
    POSIX_GUARD_RESULT(s2n_prf_wipe(conn));
    struct s2n_prf_working_space *prf_workspace = conn->prf_space;

    /* Wipe all of the sensitive stuff */
    POSIX_GUARD(s2n_connection_wipe_keys(conn));
    POSIX_GUARD(s2n_connection_reset_hmacs(conn));
    POSIX_GUARD(s2n_stuffer_wipe(&conn->alert_in));
    POSIX_GUARD(s2n_stuffer_wipe(&conn->reader_alert_out));
    POSIX_GUARD(s2n_stuffer_wipe(&conn->writer_alert_out));
    POSIX_GUARD(s2n_stuffer_wipe(&conn->client_ticket_to_decrypt));
    POSIX_GUARD(s2n_stuffer_wipe(&conn->handshake.io));
    POSIX_GUARD(s2n_stuffer_wipe(&conn->client_hello.raw_message));
    POSIX_GUARD(s2n_stuffer_wipe(&conn->header_in));
    POSIX_GUARD(s2n_stuffer_wipe(&conn->in));
    POSIX_GUARD(s2n_stuffer_wipe(&conn->out));

    POSIX_GUARD_RESULT(s2n_psk_parameters_wipe(&conn->psk_params));

    /* Wipe the I/O-related info and restore the original socket if necessary */
    POSIX_GUARD(s2n_connection_wipe_io(conn));

    POSIX_GUARD(s2n_free(&conn->client_ticket));
    POSIX_GUARD(s2n_free(&conn->status_response));
    POSIX_GUARD(s2n_free(&conn->application_protocols_overridden));
    POSIX_GUARD(s2n_free(&conn->our_quic_transport_parameters));
    POSIX_GUARD(s2n_free(&conn->peer_quic_transport_parameters));
    POSIX_GUARD(s2n_free(&conn->server_early_data_context));
    POSIX_GUARD(s2n_free(&conn->tls13_ticket_fields.session_secret));

    /* Allocate memory for handling handshakes */
    POSIX_GUARD(s2n_stuffer_resize(&conn->handshake.io, S2N_LARGE_RECORD_LENGTH));

    /* Truncate the message buffers to save memory, we will dynamically resize it as needed */
    POSIX_GUARD(s2n_stuffer_resize(&conn->client_hello.raw_message, 0));
    POSIX_GUARD(s2n_stuffer_resize(&conn->in, 0));
    POSIX_GUARD(s2n_stuffer_resize(&conn->out, 0));

    /* Remove context associated with connection */
    conn->context = NULL;
    conn->verify_host_fn_overridden = 0;
    conn->verify_host_fn = NULL;
    conn->data_for_verify_host = NULL;

    /* Clone the stuffers */
    /* ignore gcc 4.7 address warnings because dest is allocated on the stack */
    /* pragma gcc diagnostic was added in gcc 4.6 */
#if S2N_GCC_VERSION_AT_LEAST(4,6,0)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress"
#endif
    POSIX_CHECKED_MEMCPY(&alert_in, &conn->alert_in, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&reader_alert_out, &conn->reader_alert_out, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&writer_alert_out, &conn->writer_alert_out, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&client_ticket_to_decrypt, &conn->client_ticket_to_decrypt, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&handshake_io, &conn->handshake.io, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&client_hello_raw_message, &conn->client_hello.raw_message, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&header_in, &conn->header_in, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&in, &conn->in, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&out, &conn->out, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&initial_client_key, &conn->initial.client_key, sizeof(struct s2n_session_key));
    POSIX_CHECKED_MEMCPY(&initial_server_key, &conn->initial.server_key, sizeof(struct s2n_session_key));
    POSIX_CHECKED_MEMCPY(&secure_client_key, &conn->secure.client_key, sizeof(struct s2n_session_key));
    POSIX_CHECKED_MEMCPY(&secure_server_key, &conn->secure.server_key, sizeof(struct s2n_session_key));
    POSIX_GUARD(s2n_connection_save_hmac_state(&hmac_handles, conn));
#if S2N_GCC_VERSION_AT_LEAST(4,6,0)
#pragma GCC diagnostic pop
#endif

    POSIX_GUARD(s2n_connection_zero(conn, mode, config));

    POSIX_CHECKED_MEMCPY(&conn->alert_in, &alert_in, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&conn->reader_alert_out, &reader_alert_out, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&conn->writer_alert_out, &writer_alert_out, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&conn->client_ticket_to_decrypt, &client_ticket_to_decrypt, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&conn->handshake.io, &handshake_io, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&conn->client_hello.raw_message, &client_hello_raw_message, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&conn->header_in, &header_in, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&conn->in, &in, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&conn->out, &out, sizeof(struct s2n_stuffer));
    POSIX_CHECKED_MEMCPY(&conn->initial.client_key, &initial_client_key, sizeof(struct s2n_session_key));
    POSIX_CHECKED_MEMCPY(&conn->initial.server_key, &initial_server_key, sizeof(struct s2n_session_key));
    POSIX_CHECKED_MEMCPY(&conn->secure.client_key, &secure_client_key, sizeof(struct s2n_session_key));
    POSIX_CHECKED_MEMCPY(&conn->secure.server_key, &secure_server_key, sizeof(struct s2n_session_key));
    POSIX_GUARD(s2n_connection_restore_hmac_state(conn, &hmac_handles));
    conn->handshake.hashes = handshake_hashes;
    conn->prf_space = prf_workspace;

    /* Re-initialize hash and hmac states */
    POSIX_GUARD(s2n_connection_init_hmacs(conn));

    POSIX_GUARD_RESULT(s2n_psk_parameters_init(&conn->psk_params));
    conn->server_keying_material_lifetime = ONE_WEEK_IN_SEC;

    /* Require all handshakes hashes. This set can be reduced as the handshake progresses. */
    POSIX_GUARD(s2n_handshake_require_all_hashes(&conn->handshake));

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
        conn->server_protocol_version = s2n_unknown_protocol_version;
        conn->client_protocol_version = s2n_highest_protocol_version;
        conn->actual_protocol_version = s2n_highest_protocol_version;
    }

    return 0;
}

int s2n_connection_set_recv_ctx(struct s2n_connection *conn, void *ctx)
{
    POSIX_ENSURE_REF(conn);
    conn->recv_io_context = ctx;
    return 0;
}

int s2n_connection_set_send_ctx(struct s2n_connection *conn, void *ctx)
{
    POSIX_ENSURE_REF(conn);
    conn->send_io_context = ctx;
    return 0;
}

int s2n_connection_set_recv_cb(struct s2n_connection *conn, s2n_recv_fn recv)
{
    POSIX_ENSURE_REF(conn);
    conn->recv = recv;
    return 0;
}

int s2n_connection_set_send_cb(struct s2n_connection *conn, s2n_send_fn send)
{
    POSIX_ENSURE_REF(conn);
    conn->send = send;
    return 0;
}

int s2n_connection_get_client_cert_chain(struct s2n_connection *conn, uint8_t **der_cert_chain_out, uint32_t *cert_chain_len)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(der_cert_chain_out);
    POSIX_ENSURE_REF(cert_chain_len);
    POSIX_ENSURE_REF(conn->handshake_params.client_cert_chain.data);

    *der_cert_chain_out = conn->handshake_params.client_cert_chain.data;
    *cert_chain_len = conn->handshake_params.client_cert_chain.size;

    return 0;
}

int s2n_connection_get_cipher_preferences(struct s2n_connection *conn, const struct s2n_cipher_preferences **cipher_preferences)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->config);
    POSIX_ENSURE_REF(cipher_preferences);

    if (conn->security_policy_override != NULL) {
        *cipher_preferences = conn->security_policy_override->cipher_preferences;
    } else if (conn->config->security_policy != NULL) {
        *cipher_preferences = conn->config->security_policy->cipher_preferences;
    } else {
        POSIX_BAIL(S2N_ERR_INVALID_CIPHER_PREFERENCES);
    }

    POSIX_ENSURE_REF(*cipher_preferences);
    return 0;
}

int s2n_connection_get_security_policy(struct s2n_connection *conn, const struct s2n_security_policy **security_policy)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->config);
    POSIX_ENSURE_REF(security_policy);

    if (conn->security_policy_override != NULL) {
        *security_policy = conn->security_policy_override;
    } else if (conn->config->security_policy != NULL) {
        *security_policy = conn->config->security_policy;
    } else {
        POSIX_BAIL(S2N_ERR_INVALID_SECURITY_POLICY);
    }

    POSIX_ENSURE_REF(*security_policy);
    return 0;
}

int s2n_connection_get_kem_preferences(struct s2n_connection *conn, const struct s2n_kem_preferences **kem_preferences)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->config);
    POSIX_ENSURE_REF(kem_preferences);

    if (conn->security_policy_override != NULL) {
        *kem_preferences = conn->security_policy_override->kem_preferences;
    } else if (conn->config->security_policy != NULL) {
        *kem_preferences = conn->config->security_policy->kem_preferences;
    } else {
        POSIX_BAIL(S2N_ERR_INVALID_KEM_PREFERENCES);
    }

    POSIX_ENSURE_REF(*kem_preferences);
    return 0;
}

int s2n_connection_get_signature_preferences(struct s2n_connection *conn, const struct s2n_signature_preferences **signature_preferences)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->config);
    POSIX_ENSURE_REF(signature_preferences);

    if (conn->security_policy_override != NULL) {
        *signature_preferences = conn->security_policy_override->signature_preferences;
    } else if (conn->config->security_policy != NULL) {
        *signature_preferences = conn->config->security_policy->signature_preferences;
    } else {
        POSIX_BAIL(S2N_ERR_INVALID_SIGNATURE_ALGORITHMS_PREFERENCES);
    }

    POSIX_ENSURE_REF(*signature_preferences);
    return 0;

}

int s2n_connection_get_ecc_preferences(struct s2n_connection *conn, const struct s2n_ecc_preferences **ecc_preferences)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->config);
    POSIX_ENSURE_REF(ecc_preferences);

    if (conn->security_policy_override != NULL) {
        *ecc_preferences = conn->security_policy_override->ecc_preferences;
    } else if (conn->config->security_policy != NULL) {
        *ecc_preferences = conn->config->security_policy->ecc_preferences;
    } else {
        POSIX_BAIL(S2N_ERR_INVALID_ECC_PREFERENCES);
    }

    POSIX_ENSURE_REF(*ecc_preferences);
    return 0;

}

int s2n_connection_get_protocol_preferences(struct s2n_connection *conn, struct s2n_blob **protocol_preferences)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(protocol_preferences);

    *protocol_preferences = NULL;
    if (conn->application_protocols_overridden.size > 0) {
        *protocol_preferences = &conn->application_protocols_overridden;
    } else {
        *protocol_preferences = &conn->config->application_protocols;
    }

    POSIX_ENSURE_REF(*protocol_preferences);
    return 0;
}

int s2n_connection_get_client_auth_type(struct s2n_connection *conn, s2n_cert_auth_type *client_cert_auth_type)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(client_cert_auth_type);

    if (conn->client_cert_auth_type_overridden) {
        *client_cert_auth_type = conn->client_cert_auth_type;
    } else {
        *client_cert_auth_type = conn->config->client_cert_auth_type;
    }

    return 0;
}

int s2n_connection_set_client_auth_type(struct s2n_connection *conn, s2n_cert_auth_type client_cert_auth_type)
{
    conn->client_cert_auth_type_overridden = 1;
    conn->client_cert_auth_type = client_cert_auth_type;
    return 0;
}

int s2n_connection_set_read_fd(struct s2n_connection *conn, int rfd)
{
    struct s2n_blob ctx_mem = {0};
    struct s2n_socket_read_io_context *peer_socket_ctx;

    POSIX_ENSURE_REF(conn);
    POSIX_GUARD(s2n_alloc(&ctx_mem, sizeof(struct s2n_socket_read_io_context)));
    POSIX_GUARD(s2n_blob_zero(&ctx_mem));

    peer_socket_ctx = (struct s2n_socket_read_io_context *)(void *)ctx_mem.data;
    peer_socket_ctx->fd = rfd;

    s2n_connection_set_recv_cb(conn, s2n_socket_read);
    s2n_connection_set_recv_ctx(conn, peer_socket_ctx);
    conn->managed_io = 1;

    /* This is only needed if the user is using corked io.
     * Take the snapshot in case optimized io is enabled after setting the fd.
     */
    POSIX_GUARD(s2n_socket_read_snapshot(conn));

    return 0;
}

int s2n_connection_get_read_fd(struct s2n_connection *conn, int *readfd)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(readfd);
    POSIX_ENSURE((conn->managed_io && conn->recv_io_context), S2N_ERR_INVALID_STATE);

    const struct s2n_socket_read_io_context *peer_socket_ctx = conn->recv_io_context;
    *readfd = peer_socket_ctx->fd;
    return S2N_SUCCESS;
}

int s2n_connection_set_write_fd(struct s2n_connection *conn, int wfd)
{
    struct s2n_blob ctx_mem = {0};
    struct s2n_socket_write_io_context *peer_socket_ctx;

    POSIX_ENSURE_REF(conn);
    POSIX_GUARD(s2n_alloc(&ctx_mem, sizeof(struct s2n_socket_write_io_context)));

    peer_socket_ctx = (struct s2n_socket_write_io_context *)(void *)ctx_mem.data;
    peer_socket_ctx->fd = wfd;

    s2n_connection_set_send_cb(conn, s2n_socket_write);
    s2n_connection_set_send_ctx(conn, peer_socket_ctx);
    conn->managed_io = 1;

    /* This is only needed if the user is using corked io.
     * Take the snapshot in case optimized io is enabled after setting the fd.
     */
    POSIX_GUARD(s2n_socket_write_snapshot(conn));

    uint8_t ipv6;
    if (0 == s2n_socket_is_ipv6(wfd, &ipv6)) {
        conn->ipv6 = (ipv6 ? 1 : 0);
    }

    conn->write_fd_broken = 0;

    return 0;
}

int s2n_connection_get_write_fd(struct s2n_connection *conn, int *writefd)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(writefd);
    POSIX_ENSURE((conn->managed_io && conn->send_io_context), S2N_ERR_INVALID_STATE);

    const struct s2n_socket_write_io_context *peer_socket_ctx = conn->send_io_context;
    *writefd = peer_socket_ctx->fd;
    return S2N_SUCCESS;
}
int s2n_connection_set_fd(struct s2n_connection *conn, int fd)
{
    POSIX_GUARD(s2n_connection_set_read_fd(conn, fd));
    POSIX_GUARD(s2n_connection_set_write_fd(conn, fd));
    return 0;
}

int s2n_connection_use_corked_io(struct s2n_connection *conn)
{
    if (!conn->managed_io) {
        /* Caller shouldn't be trying to set s2n IO corked on non-s2n-managed IO */
        POSIX_BAIL(S2N_ERR_CORK_SET_ON_UNMANAGED);
    }
    conn->corked_io = 1;

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

const char *s2n_connection_get_cipher(struct s2n_connection *conn)
{
    PTR_ENSURE_REF(conn);
    PTR_ENSURE_REF(conn->secure.cipher_suite);

    return conn->secure.cipher_suite->name;
}

int s2n_connection_get_cipher_iana_value(struct s2n_connection *conn, uint8_t *first, uint8_t *second)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->secure.cipher_suite);
    POSIX_ENSURE_MUT(first);
    POSIX_ENSURE_MUT(second);

    /* ensure we've negotiated a cipher suite */
    POSIX_ENSURE(
        memcmp(
            conn->secure.cipher_suite->iana_value,
            s2n_null_cipher_suite.iana_value,
            sizeof(s2n_null_cipher_suite.iana_value)
        ) != 0,
        S2N_ERR_INVALID_STATE
    );

    const uint8_t *iana_value = conn->secure.cipher_suite->iana_value;
    *first = iana_value[0];
    *second = iana_value[1];

    return S2N_SUCCESS;
}

const char *s2n_connection_get_curve(struct s2n_connection *conn)
{
    PTR_ENSURE_REF(conn);

    if (conn->kex_params.server_ecc_evp_params.negotiated_curve) {
        /* TLS1.3 currently only uses ECC groups. */
        if (conn->actual_protocol_version >= S2N_TLS13 || s2n_kex_includes(conn->secure.cipher_suite->key_exchange_alg, &s2n_ecdhe)) {
            return conn->kex_params.server_ecc_evp_params.negotiated_curve->name;
        }
    }

    return "NONE";
}

const char *s2n_connection_get_kem_name(struct s2n_connection *conn)
{
    PTR_ENSURE_REF(conn);

    if (!conn->kex_params.kem_params.kem) {
        return "NONE";
    }

    return conn->kex_params.kem_params.kem->name;
}

const char *s2n_connection_get_kem_group_name(struct s2n_connection *conn)
{
    PTR_ENSURE_REF(conn);

    if (conn->actual_protocol_version < S2N_TLS13 || !conn->kex_params.client_kem_group_params.kem_group) {
        return "NONE";
    }

    return conn->kex_params.client_kem_group_params.kem_group->name;
}

int s2n_connection_get_client_protocol_version(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);

    return conn->client_protocol_version;
}

int s2n_connection_get_server_protocol_version(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);

    return conn->server_protocol_version;
}

int s2n_connection_get_actual_protocol_version(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);

    return conn->actual_protocol_version;
}

int s2n_connection_get_client_hello_version(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);

    return conn->client_hello_version;
}

int s2n_connection_client_cert_used(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);

    if (IS_CLIENT_AUTH_HANDSHAKE(conn) && is_handshake_complete(conn)) {
        if (IS_CLIENT_AUTH_NO_CERT(conn)) {
            return 0;
        }
        return 1;
    }
    return 0;
}

int s2n_connection_get_alert(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);

    S2N_ERROR_IF(s2n_stuffer_data_available(&conn->alert_in) != 2, S2N_ERR_NO_ALERT);

    uint8_t alert_code = 0;
    POSIX_GUARD(s2n_stuffer_read_uint8(&conn->alert_in, &alert_code));
    POSIX_GUARD(s2n_stuffer_read_uint8(&conn->alert_in, &alert_code));

    return alert_code;
}

int s2n_set_server_name(struct s2n_connection *conn, const char *server_name)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(server_name);

    S2N_ERROR_IF(conn->mode != S2N_CLIENT, S2N_ERR_CLIENT_MODE);

    int len = strlen(server_name);
    S2N_ERROR_IF(len > S2N_MAX_SERVER_NAME, S2N_ERR_SERVER_NAME_TOO_LONG);

    POSIX_CHECKED_MEMCPY(conn->server_name, server_name, len);

    return 0;
}

const char *s2n_get_server_name(struct s2n_connection *conn)
{
    PTR_ENSURE_REF(conn);

    if (conn->server_name[0]) {
        return conn->server_name;
    }

    PTR_GUARD_POSIX(s2n_extension_process(&s2n_client_server_name_extension, conn, &conn->client_hello.extensions));

    if (!conn->server_name[0]) {
        return NULL;
    }

    return conn->server_name;
}

const char *s2n_get_application_protocol(struct s2n_connection *conn)
{
    PTR_ENSURE_REF(conn);

    if (strlen(conn->application_protocol) == 0) {
        return NULL;
    }

    return conn->application_protocol;
}

int s2n_connection_get_session_id_length(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    /* Stateful session resumption in TLS1.3 using session id is not yet supported. */
    if (conn->actual_protocol_version >= S2N_TLS13) {
        return 0;
    }
    return conn->session_id_len;
}

int s2n_connection_get_session_id(struct s2n_connection *conn, uint8_t *session_id, size_t max_length)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(session_id);

    int session_id_len = s2n_connection_get_session_id_length(conn);

    S2N_ERROR_IF(session_id_len > max_length, S2N_ERR_SESSION_ID_TOO_LONG);

    POSIX_CHECKED_MEMCPY(session_id, conn->session_id, session_id_len);

    return session_id_len;
}

int s2n_connection_set_blinding(struct s2n_connection *conn, s2n_blinding blinding)
{
    POSIX_ENSURE_REF(conn);
    conn->blinding = blinding;

    return 0;
}

#define ONE_S  INT64_C(1000000000)
#define TEN_S  INT64_C(10000000000)

uint64_t s2n_connection_get_delay(struct s2n_connection *conn)
{
    if (!conn->delay) {
        return 0;
    }

    uint64_t elapsed;
    /* This will cast -1 to max uint64_t */
    POSIX_GUARD_RESULT(s2n_timer_elapsed(conn->config, &conn->write_timer, &elapsed));

    if (elapsed > conn->delay) {
        return 0;
    }

    return conn->delay - elapsed;
}

S2N_CLEANUP_RESULT s2n_connection_apply_error_blinding(struct s2n_connection **conn)
{
    RESULT_ENSURE_REF(conn);
    if (*conn == NULL) {
        return S2N_RESULT_OK;
    }

    int error_code = s2n_errno;
    int error_type = s2n_error_get_type(error_code);

    switch(error_type) {
        case S2N_ERR_T_OK:
            /* Ignore no error */
            return S2N_RESULT_OK;
        case S2N_ERR_T_BLOCKED:
            /* All blocking errors are retriable and should trigger no further action. */
            return S2N_RESULT_OK;
        default:
            break;
    }

    switch(error_code) {
        /* Don't invoke blinding on some of the common errors.
         *
         * Be careful adding new errors here. Disabling blinding for an
         * error that can be triggered by secret / encrypted values can
         * potentially lead to a side channel attack.
         *
         * We may want to someday add an explicit error type for these errors.
         */
        case S2N_ERR_CANCELLED:
        case S2N_ERR_CIPHER_NOT_SUPPORTED:
        case S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED:
            (*conn)->closed = 1;
            break;
        default:
            /* Apply blinding to all other errors */
            RESULT_GUARD_POSIX(s2n_connection_kill(*conn));
            break;
    }

    return S2N_RESULT_OK;
}

int s2n_connection_kill(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);

    conn->closed = 1;

    /* Delay between 10 and 30 seconds in nanoseconds */
    int64_t min = TEN_S, max = 3 * TEN_S;

    /* Keep track of the delay so that it can be enforced */
    uint64_t rand_delay = 0;
    POSIX_GUARD_RESULT(s2n_public_random(max - min, &rand_delay));

    conn->delay = min + rand_delay;

    /* Restart the write timer */
    POSIX_GUARD_RESULT(s2n_timer_start(conn->config, &conn->write_timer));

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
    PTR_ENSURE_REF(conn);
    PTR_ENSURE_REF(length);

    *length = conn->status_response.size;
    return conn->status_response.data;
}

S2N_RESULT s2n_connection_set_max_fragment_length(struct s2n_connection *conn, uint16_t max_frag_length)
{
    RESULT_ENSURE_REF(conn);

    if (conn->negotiated_mfl_code) {
        /* Respect the upper limit agreed on with the peer */
        RESULT_ENSURE_LT(conn->negotiated_mfl_code, s2n_array_len(mfl_code_to_length));
        conn->max_outgoing_fragment_length = MIN(mfl_code_to_length[conn->negotiated_mfl_code], max_frag_length);
    } else {
        conn->max_outgoing_fragment_length = max_frag_length;
    }

    /* If no buffer has been initialized yet, no need to resize.
     * The standard I/O logic will handle initializing the buffer.
     */
    if (s2n_stuffer_is_freed(&conn->out)) {
        return S2N_RESULT_OK;
    }

    uint16_t max_wire_record_size = 0;
    RESULT_GUARD(s2n_record_max_write_size(conn, conn->max_outgoing_fragment_length, &max_wire_record_size));
    if ((conn->out.blob.size < max_wire_record_size)) {
        RESULT_GUARD_POSIX(s2n_realloc(&conn->out.blob, max_wire_record_size));
    }

    return S2N_RESULT_OK;
}

int s2n_connection_prefer_throughput(struct s2n_connection *conn)
{
    POSIX_GUARD_RESULT(s2n_connection_set_max_fragment_length(conn, S2N_LARGE_FRAGMENT_LENGTH));
    return S2N_SUCCESS;
}

int s2n_connection_prefer_low_latency(struct s2n_connection *conn)
{
    POSIX_GUARD_RESULT(s2n_connection_set_max_fragment_length(conn, S2N_SMALL_FRAGMENT_LENGTH));
    return S2N_SUCCESS;
}

int s2n_connection_set_dynamic_record_threshold(struct s2n_connection *conn, uint32_t resize_threshold, uint16_t timeout_threshold)
{
    POSIX_ENSURE_REF(conn);
    S2N_ERROR_IF(resize_threshold > S2N_TLS_MAX_RESIZE_THRESHOLD, S2N_ERR_INVALID_DYNAMIC_THRESHOLD);

    conn->dynamic_record_resize_threshold = resize_threshold;
    conn->dynamic_record_timeout_threshold = timeout_threshold;
    return 0;
}

int s2n_connection_set_verify_host_callback(struct s2n_connection *conn, s2n_verify_host_fn verify_host_fn, void *data) {
    POSIX_ENSURE_REF(conn);

    conn->verify_host_fn = verify_host_fn;
    conn->data_for_verify_host = data;
    conn->verify_host_fn_overridden = 1;

    return 0;
}

int s2n_connection_recv_stuffer(struct s2n_stuffer *stuffer, struct s2n_connection *conn, uint32_t len)
{
    POSIX_ENSURE_REF(conn->recv);
    /* Make sure we have enough space to write */
    POSIX_GUARD(s2n_stuffer_reserve_space(stuffer, len));

    int r = 0;
    do {
        errno = 0;
        r = conn->recv(conn->recv_io_context, stuffer->blob.data + stuffer->write_cursor, len);
        S2N_ERROR_IF(r < 0 && errno != EINTR, S2N_ERR_RECV_STUFFER_FROM_CONN);
    } while (r < 0);

    /* Record just how many bytes we have written */
    POSIX_GUARD(s2n_stuffer_skip_write(stuffer, r));
    return r;
}

int s2n_connection_send_stuffer(struct s2n_stuffer *stuffer, struct s2n_connection *conn, uint32_t len)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->send);
    if (conn->write_fd_broken) {
        POSIX_BAIL(S2N_ERR_SEND_STUFFER_TO_CONN);
    }
    /* Make sure we even have the data */
    S2N_ERROR_IF(s2n_stuffer_data_available(stuffer) < len, S2N_ERR_STUFFER_OUT_OF_DATA);

    int w = 0;
    do {
        errno = 0;
        w = conn->send(conn->send_io_context, stuffer->blob.data + stuffer->read_cursor, len);
	if (w < 0 && errno == EPIPE) {
            conn->write_fd_broken = 1;
        }
        S2N_ERROR_IF(w < 0 && errno != EINTR, S2N_ERR_SEND_STUFFER_TO_CONN);
    } while (w < 0);

    POSIX_GUARD(s2n_stuffer_skip_read(stuffer, w));
    return w;
}

int s2n_connection_is_managed_corked(const struct s2n_connection *s2n_connection)
{
    POSIX_ENSURE_REF(s2n_connection);

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

int s2n_connection_is_client_auth_enabled(struct s2n_connection *s2n_connection)
{
    s2n_cert_auth_type auth_type;
    POSIX_GUARD(s2n_connection_get_client_auth_type(s2n_connection, &auth_type));

    return (auth_type != S2N_CERT_AUTH_NONE);
}

struct s2n_cert_chain_and_key *s2n_connection_get_selected_cert(struct s2n_connection *conn)
{
    PTR_ENSURE_REF(conn);
    return conn->handshake_params.our_chain_and_key;
}

uint8_t s2n_connection_get_protocol_version(const struct s2n_connection *conn)
{
    if (conn == NULL) {
        return S2N_UNKNOWN_PROTOCOL_VERSION;
    }

    if (conn->actual_protocol_version != S2N_UNKNOWN_PROTOCOL_VERSION) {
        return conn->actual_protocol_version;
    }

    if (conn->mode == S2N_CLIENT) {
        return conn->client_protocol_version;
    }
    return conn->server_protocol_version;
}

DEFINE_POINTER_CLEANUP_FUNC(struct s2n_cert_chain *, s2n_cert_chain_free);

int s2n_connection_get_peer_cert_chain(const struct s2n_connection *conn, struct s2n_cert_chain_and_key *cert_chain_and_key)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(cert_chain_and_key);

    DEFER_CLEANUP(struct s2n_cert_chain *cert_chain = cert_chain_and_key->cert_chain, s2n_cert_chain_free_pointer);
    struct s2n_cert **insert = &cert_chain->head;
    POSIX_ENSURE(*insert == NULL, S2N_ERR_INVALID_ARGUMENT);

    const struct s2n_x509_validator *validator = &conn->x509_validator;
    POSIX_ENSURE_REF(validator);
    POSIX_ENSURE(s2n_x509_validator_is_cert_chain_validated(validator), S2N_ERR_CERT_NOT_VALIDATED);

    /* X509_STORE_CTX_get1_chain() returns a validated cert chain if a previous call to X509_verify_cert() was successful.
     * X509_STORE_CTX_get0_chain() is a better API because it doesn't return a copy. But it's not available for Openssl 1.0.2.
     * See the comments here:
     * https://www.openssl.org/docs/man1.0.2/man3/X509_STORE_CTX_get1_chain.html
     */
    DEFER_CLEANUP(STACK_OF(X509) *cert_chain_validated = X509_STORE_CTX_get1_chain(validator->store_ctx),
                  s2n_openssl_x509_stack_pop_free);
    POSIX_ENSURE_REF(cert_chain_validated);

    for (size_t cert_idx = 0; cert_idx < sk_X509_num(cert_chain_validated); cert_idx++) {
        X509 *cert = sk_X509_value(cert_chain_validated, cert_idx);
        POSIX_ENSURE_REF(cert);
        DEFER_CLEANUP(uint8_t *cert_data = NULL, s2n_crypto_free);
        int cert_size = i2d_X509(cert, &cert_data);
        POSIX_ENSURE_GT(cert_size, 0);

        struct s2n_blob mem = { 0 };
        POSIX_GUARD(s2n_alloc(&mem, sizeof(struct s2n_cert)));

        struct s2n_cert *new_node = (struct s2n_cert *)(void *)mem.data;
        POSIX_ENSURE_REF(new_node);

        new_node->next = NULL;
        *insert = new_node;
        insert = &new_node->next;

        POSIX_GUARD(s2n_alloc(&new_node->raw, cert_size));
        POSIX_CHECKED_MEMCPY(new_node->raw.data, cert_data, cert_size);
    }

    ZERO_TO_DISABLE_DEFER_CLEANUP(cert_chain);

    return S2N_SUCCESS;
}

static S2N_RESULT s2n_signature_scheme_to_tls_iana(struct s2n_signature_scheme *sig_scheme, s2n_tls_hash_algorithm *converted_scheme)
{
    RESULT_ENSURE_REF(sig_scheme);
    RESULT_ENSURE_REF(converted_scheme);

    switch (sig_scheme->hash_alg) {
        case S2N_HASH_MD5:
            *converted_scheme = S2N_TLS_HASH_MD5;
            break;
        case S2N_HASH_SHA1:
            *converted_scheme = S2N_TLS_HASH_SHA1;
            break;
        case S2N_HASH_SHA224:
            *converted_scheme = S2N_TLS_HASH_SHA224;
            break;
        case S2N_HASH_SHA256:
            *converted_scheme = S2N_TLS_HASH_SHA256;
            break;
        case S2N_HASH_SHA384:
            *converted_scheme = S2N_TLS_HASH_SHA384;
            break;
        case S2N_HASH_SHA512:
            *converted_scheme = S2N_TLS_HASH_SHA512;
            break;
        case S2N_HASH_MD5_SHA1:
            *converted_scheme = S2N_TLS_HASH_MD5_SHA1;
            break;
        default:
            *converted_scheme = S2N_TLS_HASH_NONE;
            break;
    }

    return S2N_RESULT_OK;
}

int s2n_connection_get_selected_digest_algorithm(struct s2n_connection *conn, s2n_tls_hash_algorithm *converted_scheme)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(converted_scheme);

    POSIX_GUARD_RESULT(s2n_signature_scheme_to_tls_iana(&conn->handshake_params.conn_sig_scheme, converted_scheme));

    return S2N_SUCCESS;
}

int s2n_connection_get_selected_client_cert_digest_algorithm(struct s2n_connection *conn, s2n_tls_hash_algorithm *converted_scheme)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(converted_scheme);

    POSIX_GUARD_RESULT(s2n_signature_scheme_to_tls_iana(&conn->handshake_params.client_cert_sig_scheme, converted_scheme));
    return S2N_SUCCESS;
}

static S2N_RESULT s2n_signature_scheme_to_signature_algorithm(struct s2n_signature_scheme *sig_scheme, s2n_tls_signature_algorithm *converted_scheme)
{
    RESULT_ENSURE_REF(sig_scheme);
    RESULT_ENSURE_REF(converted_scheme);

    switch (sig_scheme->sig_alg) {
        case S2N_SIGNATURE_RSA:
            *converted_scheme = S2N_TLS_SIGNATURE_RSA;
            break;
        case S2N_SIGNATURE_ECDSA:
            *converted_scheme = S2N_TLS_SIGNATURE_ECDSA;
            break;
        case S2N_SIGNATURE_RSA_PSS_RSAE:
            *converted_scheme = S2N_TLS_SIGNATURE_RSA_PSS_RSAE;
            break;
        case S2N_SIGNATURE_RSA_PSS_PSS:
            *converted_scheme = S2N_TLS_SIGNATURE_RSA_PSS_PSS;
            break;
        default:
            *converted_scheme = S2N_TLS_SIGNATURE_ANONYMOUS;
            break;
    }

    return S2N_RESULT_OK;
}

int s2n_connection_get_selected_signature_algorithm(struct s2n_connection *conn, s2n_tls_signature_algorithm *converted_scheme)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(converted_scheme);

    POSIX_GUARD_RESULT(s2n_signature_scheme_to_signature_algorithm(&conn->handshake_params.conn_sig_scheme, converted_scheme));

    return S2N_SUCCESS;
}

int s2n_connection_get_selected_client_cert_signature_algorithm(struct s2n_connection *conn, s2n_tls_signature_algorithm *converted_scheme)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(converted_scheme);

    POSIX_GUARD_RESULT(s2n_signature_scheme_to_signature_algorithm(&conn->handshake_params.client_cert_sig_scheme, converted_scheme));

    return S2N_SUCCESS;
}
