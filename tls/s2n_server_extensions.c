/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "error/s2n_errno.h"

#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_cipher_suites.h"

#include "tls/extensions/s2n_server_renegotiation_info.h"
#include "tls/extensions/s2n_server_alpn.h"
#include "tls/extensions/s2n_server_status_request.h"
#include "tls/extensions/s2n_server_sct_list.h"
#include "tls/extensions/s2n_server_max_fragment_length.h"
#include "tls/extensions/s2n_server_session_ticket.h"
#include "tls/extensions/s2n_server_server_name.h"
#include "tls/extensions/s2n_server_supported_versions.h"
#include "tls/extensions/s2n_server_key_share.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

#define s2n_server_can_send_server_name(conn) ((conn)->server_name_used && \
        !s2n_connection_is_session_resumed((conn)))

#define s2n_server_can_send_secure_renegotiation(conn) ((conn)->secure_renegotiation && \
        (conn)->actual_protocol_version < S2N_TLS13)

#define s2n_server_can_send_nst(conn) (s2n_server_sending_nst((conn)) && \
        (conn)->actual_protocol_version < S2N_TLS13)

int s2n_server_extensions_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    uint16_t total_size = 0;

    const uint8_t application_protocol_len = strlen(conn->application_protocol);

    if (s2n_server_can_send_server_name(conn)) {
        total_size += 4;
    }

    if (application_protocol_len) {
        total_size += 7 + application_protocol_len;
    }
    if (s2n_server_can_send_ocsp(conn)) {
        total_size += 4;
    }
    if (s2n_server_can_send_secure_renegotiation(conn)) {
        total_size += 5;
    }

    if (s2n_server_can_send_kex(conn)) {
        total_size += s2n_kex_server_extension_size(conn->secure.cipher_suite->key_exchange_alg, conn);
    }

    if (s2n_server_can_send_sct_list(conn)) {
        total_size += 4 + conn->handshake_params.our_chain_and_key->sct_list.size;
    }
    if (conn->mfl_code) {
        total_size += 5;
    }
    if (s2n_server_can_send_nst(conn)) {
        total_size += 4;
    }

    if (conn->actual_protocol_version >= S2N_TLS13) {
        total_size += s2n_extensions_server_supported_versions_size();
        total_size += s2n_extensions_server_key_share_send_size(conn);
    }

    if (total_size == 0) {
        return 0;
    }

    GUARD(s2n_stuffer_write_uint16(out, total_size));

    /* Write supported versions extension if TLS 1.3 or greater */
    if (conn->actual_protocol_version >= S2N_TLS13) {
        GUARD(s2n_extensions_server_supported_versions_send(conn, out));
    }

    /* Write server name extension */
    if (s2n_server_can_send_server_name(conn)) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SERVER_NAME));
        GUARD(s2n_stuffer_write_uint16(out, 0));
    }

    if (s2n_server_can_send_kex(conn)) {
        GUARD(s2n_kex_write_server_extension(conn->secure.cipher_suite->key_exchange_alg, conn, out));
    }

    /* Write the renegotiation_info extension */
    if (s2n_server_can_send_secure_renegotiation(conn)) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_RENEGOTIATION_INFO));
        /* renegotiation_info length */
        GUARD(s2n_stuffer_write_uint16(out, 1));
        /* renegotiated_connection length. Zero since we don't support renegotiation. */
        GUARD(s2n_stuffer_write_uint8(out, 0));
    }

    /* Write ALPN extension */
    if (application_protocol_len) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_ALPN));
        GUARD(s2n_stuffer_write_uint16(out, application_protocol_len + 3));
        GUARD(s2n_stuffer_write_uint16(out, application_protocol_len + 1));
        GUARD(s2n_stuffer_write_uint8(out, application_protocol_len));
        GUARD(s2n_stuffer_write_bytes(out, (uint8_t *) conn->application_protocol, application_protocol_len));
    }

    /* Write OCSP extension */
    if (s2n_server_can_send_ocsp(conn)) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_STATUS_REQUEST));
        GUARD(s2n_stuffer_write_uint16(out, 0));
    }

    /* Write Signed Certificate Timestamp extension */
    if (s2n_server_can_send_sct_list(conn)) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SCT_LIST));
        GUARD(s2n_stuffer_write_uint16(out, conn->handshake_params.our_chain_and_key->sct_list.size));
        GUARD(s2n_stuffer_write_bytes(out, conn->handshake_params.our_chain_and_key->sct_list.data,
                                      conn->handshake_params.our_chain_and_key->sct_list.size));
    }

    if (conn->mfl_code) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_MAX_FRAG_LEN));
        GUARD(s2n_stuffer_write_uint16(out, sizeof(uint8_t)));
        GUARD(s2n_stuffer_write_uint8(out, conn->mfl_code));
    }

    /* Write session ticket extension */
    if (s2n_server_can_send_nst(conn)) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SESSION_TICKET));
        GUARD(s2n_stuffer_write_uint16(out, 0));
    }

    /* Write key share extension */
    if (conn->actual_protocol_version >= S2N_TLS13) {
        GUARD(s2n_extensions_server_key_share_send(conn, out));
    }

    return 0;
}

int s2n_server_extensions_recv(struct s2n_connection *conn, struct s2n_blob *extensions)
{
    struct s2n_stuffer in = {0};

    GUARD(s2n_stuffer_init(&in, extensions));
    GUARD(s2n_stuffer_write(&in, extensions));

    while (s2n_stuffer_data_available(&in)) {
        struct s2n_blob ext = {0};
        uint16_t extension_type, extension_size;
        struct s2n_stuffer extension = {0};

        GUARD(s2n_stuffer_read_uint16(&in, &extension_type));
        GUARD(s2n_stuffer_read_uint16(&in, &extension_size));

        ext.size = extension_size;
        ext.data = s2n_stuffer_raw_read(&in, ext.size);
        notnull_check(ext.data);

        GUARD(s2n_stuffer_init(&extension, &ext));
        GUARD(s2n_stuffer_write(&extension, &ext));

        switch (extension_type) {
        case TLS_EXTENSION_SERVER_NAME:
            GUARD(s2n_recv_server_server_name(conn, &extension));
            break;
        case TLS_EXTENSION_RENEGOTIATION_INFO:
            GUARD(s2n_recv_server_renegotiation_info_ext(conn, &extension));
            break;
        case TLS_EXTENSION_ALPN:
            GUARD(s2n_recv_server_alpn(conn, &extension));
            break;
        case TLS_EXTENSION_STATUS_REQUEST:
            GUARD(s2n_recv_server_status_request(conn, &extension));
            break;
        case TLS_EXTENSION_SCT_LIST:
            GUARD(s2n_recv_server_sct_list(conn, &extension));
            break;
        case TLS_EXTENSION_MAX_FRAG_LEN:
            GUARD(s2n_recv_server_max_fragment_length(conn, &extension));
            break;
        case TLS_EXTENSION_SESSION_TICKET:
            GUARD(s2n_recv_server_session_ticket_ext(conn, &extension));
            break;
        case TLS_EXTENSION_SUPPORTED_VERSIONS:
            if (s2n_is_tls13_enabled()) {
                GUARD(s2n_extensions_server_supported_versions_recv(conn, &extension));
            }
            break;
        case TLS_EXTENSION_KEY_SHARE:
            if (s2n_is_tls13_enabled()) {
                GUARD(s2n_extensions_server_key_share_recv(conn, &extension));
            }
            break;
        }
    }

    return 0;
}
