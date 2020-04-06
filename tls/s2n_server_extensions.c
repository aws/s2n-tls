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
#include <string.h>

#include "error/s2n_errno.h"

#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_cipher_suites.h"

#include "tls/extensions/s2n_certificate_extensions.h"
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

/* compute size server extensions send requires */
int s2n_server_extensions_send_size(struct s2n_connection *conn)
{
    int total_size = 0;
    const bool is_tls13_conn = conn->actual_protocol_version == S2N_TLS13;

    if (is_tls13_conn) {
        GUARD_UINT16_AND_INCREMENT(s2n_extensions_server_supported_versions_size(conn), total_size);
        GUARD_UINT16_AND_INCREMENT(s2n_extensions_server_key_share_send_size(conn), total_size);

        return total_size;
    }

    GUARD_UINT16_AND_INCREMENT(s2n_server_extensions_server_name_send_size(conn), total_size);
    GUARD_UINT16_AND_INCREMENT(s2n_server_extensions_alpn_send_size(conn), total_size);
    GUARD_UINT16_AND_INCREMENT(s2n_server_renegotiation_info_ext_size(conn), total_size);
    GUARD_UINT16_AND_INCREMENT(s2n_kex_server_extension_size(conn->secure.cipher_suite->key_exchange_alg, conn), total_size);
    GUARD_UINT16_AND_INCREMENT(s2n_server_extensions_max_fragment_length_send_size(conn), total_size);
    GUARD_UINT16_AND_INCREMENT(s2n_server_session_ticket_ext_size(conn), total_size);
    GUARD_UINT16_AND_INCREMENT(s2n_server_extensions_status_request_send_size(conn), total_size);
    GUARD_UINT16_AND_INCREMENT(s2n_server_extensions_sct_list_send_size(conn), total_size);

    return total_size;
}

int s2n_server_extensions_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    int total_size = s2n_server_extensions_send_size(conn);

    if (total_size == 0) {
        return 0;
    }
    inclusive_range_check(0, total_size, 65535);

    GUARD(s2n_stuffer_write_uint16(out, total_size));

    const bool is_tls13_conn = conn->actual_protocol_version == S2N_TLS13;

    /* TLS 1.3 ServerHello extensions */
    if (is_tls13_conn) {
        /* Write supported versions extension */
        GUARD(s2n_extensions_server_supported_versions_send(conn, out));
        /* Write key share extension */
        GUARD(s2n_extensions_server_key_share_send(conn, out));

        return 0;
    }

    /* TLS 1.2 Extensions */

    /* Write server name extension */
    GUARD(s2n_server_extensions_server_name_send(conn, out));

    /* Write kex extension */
    GUARD(s2n_kex_write_server_extension(conn->secure.cipher_suite->key_exchange_alg, conn, out));
    
    /* Write the renegotiation_info extension */
    GUARD(s2n_send_server_renegotiation_info_ext(conn, out));

    /* Write ALPN extension */
    GUARD(s2n_server_extensions_alpn_send(conn, out));

    /* Write OCSP extension */
    GUARD(s2n_server_extensions_status_request_send(conn, out));

    /* Write Signed Certificate Timestamp extension */
    GUARD(s2n_server_extensions_sct_list_send(conn, out));

    /* Write max fragment length extension */
    GUARD(s2n_server_extensions_max_fragment_length_send(conn, out));

    /* Write session ticket extension */
    GUARD(s2n_send_server_session_ticket_ext(conn, out));

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
