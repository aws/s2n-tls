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

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_signature_algorithms.h"
#include "tls/s2n_tls_digest_preferences.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_client_extensions.h"
#include "tls/s2n_resume.h"

#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

static int s2n_recv_client_signature_algorithms(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_alpn(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_status_request(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_elliptic_curves(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_ec_point_formats(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_renegotiation_info(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_sct_list(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_max_frag_len(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_session_ticket_ext(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_pq_kem_extension(struct s2n_connection *conn, struct s2n_stuffer *extension);

static int s2n_send_client_signature_algorithms_extension(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    /* The extension header */
    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SIGNATURE_ALGORITHMS));

    /* Each hash-signature-alg pair is two bytes, and there's another two bytes for
     * the extension length field.
     */
    uint16_t preferred_hashes_len = sizeof(s2n_preferred_hashes) / sizeof(s2n_preferred_hashes[0]);
    uint16_t num_signature_algs = sizeof(s2n_preferred_signature_algorithms) / sizeof(s2n_preferred_signature_algorithms[0]);
    uint16_t preferred_hash_sigalg_size = preferred_hashes_len * num_signature_algs * 2;
    uint16_t extension_len_field_size = 2;

    GUARD(s2n_stuffer_write_uint16(out, extension_len_field_size + preferred_hash_sigalg_size));
    GUARD(s2n_send_supported_signature_algorithms(out));

    return 0;
}

int s2n_client_extensions_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    uint16_t total_size = 0;
    uint16_t num_signature_algs = sizeof(s2n_preferred_signature_algorithms) / sizeof(s2n_preferred_signature_algorithms[0]);

    /* Signature algorithms */
    if (conn->actual_protocol_version == S2N_TLS12) {
        total_size += (sizeof(s2n_preferred_hashes) * num_signature_algs * 2) + 6;
    }

    struct s2n_blob *client_app_protocols;
    GUARD(s2n_connection_get_protocol_preferences(conn, &client_app_protocols));

    uint16_t application_protocols_len = client_app_protocols->size;
    uint16_t server_name_len = strlen(conn->server_name);
    uint16_t mfl_code_len = sizeof(conn->config->mfl_code);
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

    if (s2n_is_ecc_enabled(cipher_preferences)) {
        /* Write ECC extensions: Supported Curves and Supported Point Formats */
        int ec_curves_count = sizeof(s2n_ecc_supported_curves) / sizeof(s2n_ecc_supported_curves[0]);
        total_size += 12 + ec_curves_count * 2;
    }

    if (s2n_is_sike_enabled(cipher_preferences)) {
        int sike_params_count = sizeof(s2n_sike_supported_params) / sizeof(s2n_sike_supported_params[0]);
        /* 2 for the extension id, 2 for overall length, 2 for length of the list, and each enum is 2 bytes  */
        total_size += 6 + sike_params_count * 2;
    }

    GUARD(s2n_stuffer_write_uint16(out, total_size));

    if (conn->actual_protocol_version == S2N_TLS12) {
        GUARD(s2n_send_client_signature_algorithms_extension(conn, out));
    }

    if (server_name_len) {
        /* Write the server name */
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SERVER_NAME));
        GUARD(s2n_stuffer_write_uint16(out, server_name_len + 5));

        /* Size of all of the server names */
        GUARD(s2n_stuffer_write_uint16(out, server_name_len + 3));

        /* Name type - host name, RFC3546 */
        GUARD(s2n_stuffer_write_uint8(out, 0));

        struct s2n_blob server_name = {0};
        server_name.data = (uint8_t *) conn->server_name;
        server_name.size = server_name_len;
        GUARD(s2n_stuffer_write_uint16(out, server_name_len));
        GUARD(s2n_stuffer_write(out, &server_name));
    }

    /* Write ALPN extension */
    if (application_protocols_len) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_ALPN));
        GUARD(s2n_stuffer_write_uint16(out, application_protocols_len + 2));
        GUARD(s2n_stuffer_write_uint16(out, application_protocols_len));
        GUARD(s2n_stuffer_write(out, client_app_protocols));
    }

    if (conn->config->status_request_type != S2N_STATUS_REQUEST_NONE) {
        /* We only support OCSP */
        eq_check(conn->config->status_request_type, S2N_STATUS_REQUEST_OCSP);
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_STATUS_REQUEST));
        GUARD(s2n_stuffer_write_uint16(out, 5));
        GUARD(s2n_stuffer_write_uint8(out, (uint8_t) conn->config->status_request_type));
        GUARD(s2n_stuffer_write_uint16(out, 0));
        GUARD(s2n_stuffer_write_uint16(out, 0));
    }

    /* Write Certificate Transparency extension */
    if (conn->config->ct_type != S2N_CT_SUPPORT_NONE) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SCT_LIST));
        GUARD(s2n_stuffer_write_uint16(out, 0));
    }

    /* Write Maximum Fragmentation Length extension */
    if (conn->config->mfl_code != S2N_TLS_MAX_FRAG_LEN_EXT_NONE) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_MAX_FRAG_LEN));
        GUARD(s2n_stuffer_write_uint16(out, mfl_code_len));
        GUARD(s2n_stuffer_write_uint8(out, conn->config->mfl_code));
    }

    /* Write Session Tickets extension */
    if (conn->config->use_tickets) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SESSION_TICKET));
        GUARD(s2n_stuffer_write_uint16(out, client_ticket_len));
        GUARD(s2n_stuffer_write(out, &conn->client_ticket));
    }

    /*
     * RFC 4492: Clients SHOULD send both the Supported Elliptic Curves Extension
     * and the Supported Point Formats Extension.
     */
    if (s2n_is_ecc_enabled(cipher_preferences)) {
        int ec_curves_count = sizeof(s2n_ecc_supported_curves) / sizeof(s2n_ecc_supported_curves[0]);
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_ELLIPTIC_CURVES));
        GUARD(s2n_stuffer_write_uint16(out, 2 + ec_curves_count * 2));
        /* Curve list len */
        GUARD(s2n_stuffer_write_uint16(out, ec_curves_count * 2));
        /* Curve list */
        for (int i = 0; i < ec_curves_count; i++) {
            GUARD(s2n_stuffer_write_uint16(out, s2n_ecc_supported_curves[i].iana_id));
        }

        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_EC_POINT_FORMATS));
        GUARD(s2n_stuffer_write_uint16(out, 2));
        /* Point format list len */
        GUARD(s2n_stuffer_write_uint8(out, 1));
        /* Only allow uncompressed format */
        GUARD(s2n_stuffer_write_uint8(out, 0));
    }

    if (s2n_is_sike_enabled(cipher_preferences)) {
        int sike_params_count = sizeof(s2n_sike_supported_params) / sizeof(s2n_sike_supported_params[0]);
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_PQ_KEM_PARAMETERS));
        /* Overall length */
        GUARD(s2n_stuffer_write_uint16(out, 2 + sike_params_count * 2));
        /* Length of parameters in bytes */
        GUARD(s2n_stuffer_write_uint16(out, sike_params_count * 2));
        for (int i = 0; i < sike_params_count; i++) {
            GUARD(s2n_stuffer_write_uint16(out, s2n_sike_supported_params[i].kem_extension_id));
        }
    }

    return 0;
}

int s2n_client_extensions_recv(struct s2n_connection *conn, struct s2n_array *parsed_extensions)
{
    for (int i = 0; i < parsed_extensions->num_of_elements; i++) {
        struct s2n_client_hello_parsed_extension *parsed_extension = s2n_array_get(parsed_extensions, i);
        notnull_check(parsed_extension);

        struct s2n_stuffer extension = {{0}};
        GUARD(s2n_stuffer_init(&extension, &parsed_extension->extension));
        GUARD(s2n_stuffer_write(&extension, &parsed_extension->extension));

        switch (parsed_extension->extension_type) {
        case TLS_EXTENSION_SERVER_NAME:
            GUARD(s2n_parse_client_hello_server_name(conn, &extension));
            break;
        case TLS_EXTENSION_SIGNATURE_ALGORITHMS:
            GUARD(s2n_recv_client_signature_algorithms(conn, &extension));
            break;
        case TLS_EXTENSION_ALPN:
            GUARD(s2n_recv_client_alpn(conn, &extension));
            break;
        case TLS_EXTENSION_STATUS_REQUEST:
            GUARD(s2n_recv_client_status_request(conn, &extension));
            break;
        case TLS_EXTENSION_ELLIPTIC_CURVES:
            GUARD(s2n_recv_client_elliptic_curves(conn, &extension));
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
        }
    }

    return 0;
}

int s2n_parse_client_hello_server_name(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    if (conn->server_name[0]) {
        /* already parsed server name extension, exit early */
        return 0;
    }

    uint16_t size_of_all;
    uint8_t server_name_type;
    uint16_t server_name_len;
    uint8_t *server_name;

    GUARD(s2n_stuffer_read_uint16(extension, &size_of_all));
    if (size_of_all > s2n_stuffer_data_available(extension) || size_of_all < 3) {
        /* the size of all server names is incorrect, ignore the extension */
        return 0;
    }

    GUARD(s2n_stuffer_read_uint8(extension, &server_name_type));
    if (server_name_type != 0) {
        /* unknown server name type, ignore the extension */
        return 0;
    }

    GUARD(s2n_stuffer_read_uint16(extension, &server_name_len));
    if (server_name_len + 3 > size_of_all) {
        /* the server name length is incorrect, ignore the extension */
        return 0;
    }

    if (server_name_len > sizeof(conn->server_name) - 1) {
        /* the server name is too long, ignore the extension */
        return 0;
    }

    notnull_check(server_name = s2n_stuffer_raw_read(extension, server_name_len));

    /* copy the first server name */
    memcpy_check(conn->server_name, server_name, server_name_len);
    return 0;
}

static int s2n_recv_client_signature_algorithms(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    return s2n_recv_supported_signature_algorithms(conn, extension, &conn->handshake_params.client_sig_hash_algs);
}

static int s2n_recv_client_alpn(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint16_t size_of_all;
    struct s2n_stuffer client_protos = {{0}};
    struct s2n_stuffer server_protos = {{0}};

    struct s2n_blob *server_app_protocols;
    GUARD(s2n_connection_get_protocol_preferences(conn, &server_app_protocols));

    if (!server_app_protocols->size) {
        /* No protocols configured, nothing to do */
        return 0;
    }

    GUARD(s2n_stuffer_read_uint16(extension, &size_of_all));
    if (size_of_all > s2n_stuffer_data_available(extension) || size_of_all < 3) {
        /* Malformed length, ignore the extension */
        return 0;
    }

    struct s2n_blob client_app_protocols = {
        .data = s2n_stuffer_raw_read(extension, size_of_all),
        .size = size_of_all
    };
    notnull_check(client_app_protocols.data);

    /* Find a matching protocol */
    GUARD(s2n_stuffer_init(&client_protos, &client_app_protocols));
    GUARD(s2n_stuffer_write(&client_protos, &client_app_protocols));
    GUARD(s2n_stuffer_init(&server_protos, server_app_protocols));
    GUARD(s2n_stuffer_write(&server_protos, server_app_protocols));

    while (s2n_stuffer_data_available(&server_protos)) {
        uint8_t length;
        uint8_t server_protocol[255];
        GUARD(s2n_stuffer_read_uint8(&server_protos, &length));
        GUARD(s2n_stuffer_read_bytes(&server_protos, server_protocol, length));

        while (s2n_stuffer_data_available(&client_protos)) {
            uint8_t client_length;
            GUARD(s2n_stuffer_read_uint8(&client_protos, &client_length));
            S2N_ERROR_IF(client_length > s2n_stuffer_data_available(&client_protos), S2N_ERR_BAD_MESSAGE);
            if (client_length != length) {
                GUARD(s2n_stuffer_skip_read(&client_protos, client_length));
            } else {
                uint8_t client_protocol[255];
                GUARD(s2n_stuffer_read_bytes(&client_protos, client_protocol, client_length));
                if (memcmp(client_protocol, server_protocol, client_length) == 0) {
                    memcpy_check(conn->application_protocol, client_protocol, client_length);
                    conn->application_protocol[client_length] = '\0';
                    return 0;
                }
            }
        }

        GUARD(s2n_stuffer_reread(&client_protos));
    }
    return 0;
}

static int s2n_recv_client_status_request(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    if (s2n_stuffer_data_available(extension) < 5) {
        /* Malformed length, ignore the extension */
        return 0;
    }
    uint8_t type;
    GUARD(s2n_stuffer_read_uint8(extension, &type));
    if (type != (uint8_t) S2N_STATUS_REQUEST_OCSP) {
        /* We only support OCSP (type 1), ignore the extension */
        return 0;
    }
    conn->status_type = (s2n_status_request_type) type;
    return 0;
}

static int s2n_recv_client_elliptic_curves(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint16_t size_of_all;
    struct s2n_blob proposed_curves = {0};

    GUARD(s2n_stuffer_read_uint16(extension, &size_of_all));
    if (size_of_all > s2n_stuffer_data_available(extension) || size_of_all % 2) {
        /* Malformed length, ignore the extension */
        return 0;
    }

    proposed_curves.size = size_of_all;
    proposed_curves.data = s2n_stuffer_raw_read(extension, proposed_curves.size);
    notnull_check(proposed_curves.data);

    if (s2n_ecc_find_supported_curve(&proposed_curves, &conn->secure.server_ecc_params.negotiated_curve) != 0) {
        /* Can't agree on a curve, ECC is not allowed. Return success to proceed with the handshake. */
        conn->secure.server_ecc_params.negotiated_curve = NULL;
    }
    return 0;
}

static int s2n_recv_client_ec_point_formats(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    /**
     * Only uncompressed points are supported by the server and the client must include it in
     * the extension. Just skip the extension.
     */
    conn->ec_point_formats = 1;
    return 0;
}

static int s2n_recv_client_renegotiation_info(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    /* RFC5746 Section 3.2: The renegotiated_connection field is of zero length for the initial handshake. */
    uint8_t renegotiated_connection_len;
    GUARD(s2n_stuffer_read_uint8(extension, &renegotiated_connection_len));
    S2N_ERROR_IF(s2n_stuffer_data_available(extension) || renegotiated_connection_len, S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);

    conn->secure_renegotiation = 1;
    return 0;
}

static int s2n_recv_client_sct_list(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    conn->ct_level_requested = S2N_CT_SUPPORT_REQUEST;
    /* Skip reading the extension, per RFC6962 (3.1.1) it SHOULD be empty anyway  */
    return 0;
}


static int s2n_recv_client_max_frag_len(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    if (!conn->config->accept_mfl) {
        return 0;
    }

    uint8_t mfl_code;
    GUARD(s2n_stuffer_read_uint8(extension, &mfl_code));
    if (mfl_code > S2N_TLS_MAX_FRAG_LEN_4096 || mfl_code_to_length[mfl_code] > S2N_TLS_MAXIMUM_FRAGMENT_LENGTH) {
        return 0;
    }

    conn->mfl_code = mfl_code;
    conn->max_outgoing_fragment_length = mfl_code_to_length[mfl_code];
    return 0;
}

static int s2n_recv_client_session_ticket_ext(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    if (conn->config->use_tickets != 1) {
        /* Ignore the extension. */
        return 0;
    }

    /* s2n server does not support session ticket with CLIENT_AUTH enabled */
    if (s2n_connection_is_client_auth_enabled(conn) > 0) {
        return 0;
    }

    if (s2n_stuffer_data_available(extension) == 0 && s2n_config_is_encrypt_decrypt_key_available(conn->config) == 1) {
        conn->session_ticket_status = S2N_NEW_TICKET;
        return 0;
    }

    if (s2n_stuffer_data_available(extension) == S2N_TICKET_SIZE_IN_BYTES) {
        conn->session_ticket_status = S2N_DECRYPT_TICKET;
        GUARD(s2n_stuffer_copy(extension, &conn->client_ticket_to_decrypt, S2N_TICKET_SIZE_IN_BYTES));
    }

    return 0;
}
static int s2n_recv_pq_kem_extension(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint16_t size_of_all;
    struct s2n_blob proposed_kems = {0};

    GUARD(s2n_stuffer_read_uint16(extension, &size_of_all));
    if (size_of_all > s2n_stuffer_data_available(extension) || size_of_all % 2) {
        /* Malformed length, ignore the extension */
        return 0;
    }

    proposed_kems.size = size_of_all;
    proposed_kems.data = s2n_stuffer_raw_read(extension, proposed_kems.size);
    notnull_check(proposed_kems.data);

    const struct s2n_kem *match = NULL;
    int num_params = sizeof(s2n_sike_supported_params) / sizeof(s2n_sike_supported_params[0]);
    s2n_kem_find_supported_kem(&proposed_kems, s2n_sike_supported_params, num_params, &match);
    conn->secure.s2n_kem_keys.negotiated_kem = match;

    return 0;
}
