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

#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_signature_algorithms.h"
#include "tls/s2n_tls_digest_preferences.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_client_extensions.h"
#include "tls/s2n_resume.h"
#include "tls/s2n_ecc_preferences.h"

#include "extensions/s2n_client_supported_versions.h"
#include "extensions/s2n_client_signature_algorithms.h"
#include "extensions/s2n_client_max_frag_len.h"
#include "extensions/s2n_client_session_ticket.h"
#include "extensions/s2n_client_server_name.h"
#include "extensions/s2n_client_alpn.h"
#include "extensions/s2n_client_status_request.h"
#include "extensions/s2n_client_key_share.h"
#include "extensions/s2n_client_sct_list.h"
#include "extensions/s2n_client_supported_groups.h"
#include "extensions/s2n_client_pq_kem.h"
#include "extensions/s2n_client_ec_point_format.h"
#include "extensions/s2n_client_renegotiation_info.h"

#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

int s2n_client_extensions_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    uint16_t total_size = 0;
    uint16_t pq_kem_list_size = 0;

    /* SignatureScheme */
    if (conn->actual_protocol_version >= S2N_TLS12) {
        total_size += s2n_extensions_client_signature_algorithms_size(conn);
    }

    struct s2n_blob *client_app_protocols;
    GUARD(s2n_connection_get_protocol_preferences(conn, &client_app_protocols));

    uint16_t application_protocols_len = client_app_protocols->size;
    uint16_t server_name_len = strlen(conn->server_name);
    uint16_t client_ticket_len = conn->client_ticket.size;

    if (server_name_len) {
        total_size += 9 + server_name_len;
    }
    if (application_protocols_len) {
        total_size += 6 + application_protocols_len;
    }
    if (conn->config->status_request_type != S2N_STATUS_REQUEST_NONE) {
        total_size += 9;
    }
    if (conn->config->ct_type != S2N_CT_SUPPORT_NONE) {
        total_size += 4;
    }
    if (conn->config->mfl_code != S2N_TLS_MAX_FRAG_LEN_EXT_NONE) {
        total_size += 5;
    }
    if (conn->config->use_tickets) {
        total_size += 4 + client_ticket_len;
    }

    const struct s2n_cipher_preferences *cipher_preferences;
    GUARD(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));

    notnull_check(conn->config);
    const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
    notnull_check(ecc_pref);

    const uint8_t ecc_extension_required = s2n_ecc_extension_required(cipher_preferences);
    if (ecc_extension_required) {
        /* Write ECC extensions: Supported Curves and Supported Point Formats */
        total_size += 12 + ecc_pref->count * 2;
    }

    const uint8_t pq_kem_extension_required = s2n_pq_kem_extension_required(cipher_preferences);
    /* pq_kem_extension_required is true if and only if cipher_preferences->kem_count > 0 */
    if (pq_kem_extension_required) {
        /* 2 for the extension id, 2 for overall length, 2 for length of the list, and 2 for each kem ID*/
        pq_kem_list_size = cipher_preferences->kem_count * 2;
        total_size += 6 + pq_kem_list_size;
    }

    if (conn->client_protocol_version >= S2N_TLS13) {
        total_size += s2n_extensions_client_supported_versions_size(conn);
        total_size += s2n_extensions_client_key_share_size(conn);
    }

    GUARD(s2n_stuffer_write_uint16(out, total_size));

    if (conn->client_protocol_version >= S2N_TLS13) {
        GUARD(s2n_extensions_client_supported_versions_send(conn, out));
        GUARD(s2n_extensions_client_key_share_send(conn, out));
    }

    if (conn->actual_protocol_version >= S2N_TLS12) {
        GUARD(s2n_extensions_client_signature_algorithms_send(conn, out));
    }

    if (server_name_len) {
        GUARD(s2n_extensions_client_server_name_send(conn, out));
    }

    /* Write ALPN extension */
    if (application_protocols_len) {
        GUARD(s2n_extensions_client_alpn_send(conn, out));
    }

    if (conn->config->status_request_type != S2N_STATUS_REQUEST_NONE) {
        /* We only support OCSP */
        eq_check(conn->config->status_request_type, S2N_STATUS_REQUEST_OCSP);
        GUARD(s2n_extensions_client_status_request_send(conn, out));
    }

    /* Write Certificate Transparency extension */
    if (conn->config->ct_type != S2N_CT_SUPPORT_NONE) {
        GUARD(s2n_extensions_client_sct_list_send(conn, out));
    }

    /* Write Maximum Fragmentation Length extension */
    if (conn->config->mfl_code != S2N_TLS_MAX_FRAG_LEN_EXT_NONE) {
        GUARD(s2n_extensions_client_max_frag_len_send(conn, out));
    }

    /* Write Session Tickets extension */
    if (conn->config->use_tickets) {
        GUARD(s2n_extensions_client_session_ticket_send(conn, out));
    }

    /*
     * RFC 4492: Clients SHOULD send both the Supported Elliptic Curves Extension (renamed
     * Supported Groups in TLS 1.3 RFC 8446) and the Supported Point Formats Extension.
     */
    if (ecc_extension_required) {
        GUARD(s2n_extensions_client_supported_groups_send(conn, out));
    }

    if (pq_kem_extension_required) {
        GUARD(s2n_extensions_client_pq_kem_send(conn, out, pq_kem_list_size));
    }

    return 0;
}

int s2n_client_extensions_recv(struct s2n_connection *conn, struct s2n_array *parsed_extensions)
{
    for (int i = 0; i < parsed_extensions->num_of_elements; i++) {
        struct s2n_client_hello_parsed_extension *parsed_extension = s2n_array_get(parsed_extensions, i);
        notnull_check(parsed_extension);

        struct s2n_stuffer extension = {0};
        GUARD(s2n_stuffer_init(&extension, &parsed_extension->extension));
        GUARD(s2n_stuffer_write(&extension, &parsed_extension->extension));

        switch (parsed_extension->extension_type) {
        case TLS_EXTENSION_SERVER_NAME:
            GUARD(s2n_parse_client_hello_server_name(conn, &extension));
            break;
        case TLS_EXTENSION_SIGNATURE_ALGORITHMS:
            GUARD(s2n_extensions_client_signature_algorithms_recv(conn, &extension));
            break;
        case TLS_EXTENSION_ALPN:
            GUARD(s2n_recv_client_alpn(conn, &extension));
            break;
        case TLS_EXTENSION_STATUS_REQUEST:
            GUARD(s2n_recv_client_status_request(conn, &extension));
            break;
        case TLS_EXTENSION_SUPPORTED_GROUPS:
            GUARD(s2n_recv_client_supported_groups(conn, &extension));
            break;
        case TLS_EXTENSION_EC_POINT_FORMATS:
            GUARD(s2n_recv_client_ec_point_formats(conn, &extension));
            break;
        case TLS_EXTENSION_RENEGOTIATION_INFO:
            GUARD(s2n_recv_client_renegotiation_info(conn, &extension));
            break;
        case TLS_EXTENSION_SCT_LIST:
            GUARD(s2n_recv_client_sct_list(conn, &extension));
            break;
        case TLS_EXTENSION_MAX_FRAG_LEN:
            GUARD(s2n_recv_client_max_frag_len(conn, &extension));
            break;
        case TLS_EXTENSION_SESSION_TICKET:
            GUARD(s2n_recv_client_session_ticket_ext(conn, &extension));
            break;
        case TLS_EXTENSION_PQ_KEM_PARAMETERS:
            GUARD(s2n_recv_pq_kem_extension(conn, &extension));
            break;
        case TLS_EXTENSION_SUPPORTED_VERSIONS:
            /* allow supported versions to be parsed to get highest client version */
            if (s2n_is_tls13_enabled()) {
                GUARD(s2n_extensions_client_supported_versions_recv(conn, &extension));
            }
            break;
        case TLS_EXTENSION_KEY_SHARE:
            /* parse key share only if negiotated protocol is in TLS 1.3 */
            if (s2n_is_tls13_enabled() && conn->actual_protocol_version == S2N_TLS13) {
                GUARD(s2n_extensions_client_key_share_recv(conn, &extension));
            }
            break;
        }
    }

    return 0;
}
