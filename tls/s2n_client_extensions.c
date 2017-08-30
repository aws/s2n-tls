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

#include "tls/s2n_tls_digest_preferences.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_connection.h"

#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "tls/s2n_client_extensions.h"

static int s2n_recv_client_server_name(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_alpn(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_status_request(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_elliptic_curves(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_ec_point_formats(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_renegotiation_info(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_sct_list(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_client_max_frag_len(struct s2n_connection *conn, struct s2n_stuffer *extension);

static int s2n_send_client_signature_algorithms_extension(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    /* The extension header */
    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SIGNATURE_ALGORITHMS));

    /* Each hash-signature-alg pair is two bytes, and there's another two bytes for
     * the extension length field.
     */
    uint16_t preferred_hashes_len = sizeof(s2n_preferred_hashes) / sizeof(s2n_preferred_hashes[0]);
    uint16_t preferred_hashes_size = preferred_hashes_len * 2;
    uint16_t extension_len_field_size = 2;

    GUARD(s2n_stuffer_write_uint16(out, extension_len_field_size + preferred_hashes_size));
    GUARD(s2n_send_client_signature_algorithms(out));

    return 0;
}

int s2n_client_extensions_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    uint16_t total_size = 0;

    /* Signature algorithms */
    if (conn->actual_protocol_version == S2N_TLS12) {
        total_size += (sizeof(s2n_preferred_hashes) * 2) + 6;
    }

    uint16_t application_protocols_len = conn->config->application_protocols.size;
    uint16_t server_name_len = strlen(conn->server_name);
    uint16_t mfl_code_len = sizeof(conn->config->mfl_code);

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

    /* Write ECC extensions: Supported Curves and Supported Point Formats */
    int ec_curves_count = sizeof(s2n_ecc_supported_curves) / sizeof(s2n_ecc_supported_curves[0]);
    total_size += 12 + ec_curves_count * 2;

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

        struct s2n_blob server_name;
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
        GUARD(s2n_stuffer_write(out, &conn->config->application_protocols));
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

    /*
     * RFC 4492: Clients SHOULD send both the Supported Elliptic Curves Extension
     * and the Supported Point Formats Extension.
     */
    {
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

    return 0;
}

int s2n_client_extensions_recv(struct s2n_connection *conn, struct s2n_blob *extensions)
{
    struct s2n_stuffer in;

    GUARD(s2n_stuffer_init(&in, extensions));
    GUARD(s2n_stuffer_write(&in, extensions));

    while (s2n_stuffer_data_available(&in)) {
        struct s2n_blob ext;
        uint16_t extension_type, extension_size;
        struct s2n_stuffer extension;

        GUARD(s2n_stuffer_read_uint16(&in, &extension_type));
        GUARD(s2n_stuffer_read_uint16(&in, &extension_size));

        ext.size = extension_size;
        lte_check(extension_size, s2n_stuffer_data_available(&in));
        ext.data = s2n_stuffer_raw_read(&in, ext.size);
        notnull_check(ext.data);

        GUARD(s2n_stuffer_init(&extension, &ext));
        GUARD(s2n_stuffer_write(&extension, &ext));

        switch (extension_type) {
        case TLS_EXTENSION_SERVER_NAME:
            GUARD(s2n_recv_client_server_name(conn, &extension));
            break;
        case TLS_EXTENSION_SIGNATURE_ALGORITHMS:
            GUARD(s2n_recv_client_signature_algorithms(conn, &extension, &conn->secure.conn_hash_alg, &conn->secure.conn_sig_alg));
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
        }
    }

    return 0;
}

static int s2n_recv_client_server_name(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
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

int s2n_send_client_signature_algorithms(struct s2n_stuffer *out)
{
    /* The array of hashes and signature algorithms we support */
    uint16_t preferred_hashes_len = sizeof(s2n_preferred_hashes) / sizeof(s2n_preferred_hashes[0]);
    uint16_t preferred_hashes_size = preferred_hashes_len * 2;
    GUARD(s2n_stuffer_write_uint16(out, preferred_hashes_size));

    for (int i =  0; i < preferred_hashes_len; i++) {
        GUARD(s2n_stuffer_write_uint8(out, s2n_preferred_hashes[i]));
        GUARD(s2n_stuffer_write_uint8(out, TLS_SIGNATURE_ALGORITHM_RSA));
    }
    return 0;
}

int s2n_recv_client_signature_algorithms(struct s2n_connection *conn, struct s2n_stuffer *in, s2n_hash_algorithm *hash, s2n_signature_algorithm *sig)
{
    uint16_t length_of_all_pairs;
    GUARD(s2n_stuffer_read_uint16(in, &length_of_all_pairs));
    if (length_of_all_pairs > s2n_stuffer_data_available(in)) {
        /* Malformed length, ignore the extension */
        return 0;
    }

    if (length_of_all_pairs % 2 || s2n_stuffer_data_available(in) % 2) {
        /* Pairs occur in two byte lengths. Malformed length, ignore the extension. */
        return 0;
    }

    int pairs_available = length_of_all_pairs / 2;
    GUARD(s2n_choose_preferred_signature_hash_pair(in, pairs_available, hash, sig));

    return 0;
}

int s2n_choose_preferred_signature_hash_pair(struct s2n_stuffer *in, int pairs_available,
        s2n_hash_algorithm *hash_alg_out, s2n_signature_algorithm *signature_alg_out)
{
    uint8_t *their_hash_sig_pairs = s2n_stuffer_raw_read(in, pairs_available * 2);
    notnull_check(their_hash_sig_pairs);

    for(int our_hash_idx = 0; our_hash_idx < sizeof(s2n_preferred_hashes); our_hash_idx++) {
        for(int their_sig_hash_idx = 0; their_sig_hash_idx < pairs_available; their_sig_hash_idx++){
            uint8_t their_hash_alg = their_hash_sig_pairs[2 * their_sig_hash_idx];
            uint8_t their_sig_alg = their_hash_sig_pairs[2 * their_sig_hash_idx + 1];

            if(their_sig_alg == TLS_SIGNATURE_ALGORITHM_RSA && their_hash_alg == s2n_preferred_hashes[our_hash_idx]) {
                *hash_alg_out = s2n_hash_tls_to_alg[their_hash_alg];
                *signature_alg_out = their_sig_alg;
                return 0;
            }
        }
    }

    S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
}

static int s2n_recv_client_alpn(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint16_t size_of_all;
    struct s2n_stuffer client_protos;
    struct s2n_stuffer server_protos;

    if (!conn->config->application_protocols.size) {
        /* No protocols configured, nothing to do */
        return 0;
    }

    GUARD(s2n_stuffer_read_uint16(extension, &size_of_all));
    if (size_of_all > s2n_stuffer_data_available(extension) || size_of_all < 3) {
        /* Malformed length, ignore the extension */
        return 0;
    }

    struct s2n_blob application_protocols = {
        .data = s2n_stuffer_raw_read(extension, size_of_all),
        .size = size_of_all
    };
    notnull_check(application_protocols.data);

    /* Find a matching protocol */
    GUARD(s2n_stuffer_init(&client_protos, &application_protocols));
    GUARD(s2n_stuffer_write(&client_protos, &application_protocols));
    GUARD(s2n_stuffer_init(&server_protos, &conn->config->application_protocols));
    GUARD(s2n_stuffer_write(&server_protos, &conn->config->application_protocols));

    while (s2n_stuffer_data_available(&server_protos)) {
        uint8_t length;
        uint8_t protocol[255];
        GUARD(s2n_stuffer_read_uint8(&server_protos, &length));
        GUARD(s2n_stuffer_read_bytes(&server_protos, protocol, length));

        while (s2n_stuffer_data_available(&client_protos)) {
            uint8_t client_length;
            GUARD(s2n_stuffer_read_uint8(&client_protos, &client_length));
            if (client_length > s2n_stuffer_data_available(&client_protos)) {
                S2N_ERROR(S2N_ERR_BAD_MESSAGE);
            }
            if (client_length != length) {
                GUARD(s2n_stuffer_skip_read(&client_protos, client_length));
            } else {
                uint8_t client_protocol[255];
                GUARD(s2n_stuffer_read_bytes(&client_protos, client_protocol, client_length));
                if (memcmp(client_protocol, protocol, client_length) == 0) {
                    memcpy_check(conn->application_protocol, client_protocol, client_length);
                    conn->application_protocol[client_length] = '\0';
                    return 0;
                }
            }
        }

        GUARD(s2n_stuffer_reread(&client_protos));
    }

    S2N_ERROR(S2N_ERR_NO_APPLICATION_PROTOCOL);
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
    struct s2n_blob proposed_curves;

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
    return 0;
}

static int s2n_recv_client_renegotiation_info(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    /* RFC5746 Section 3.2: The renegotiated_connection field is of zero length for the initial handshake. */
    uint8_t renegotiated_connection_len;
    GUARD(s2n_stuffer_read_uint8(extension, &renegotiated_connection_len));
    if (s2n_stuffer_data_available(extension) || renegotiated_connection_len) {
        S2N_ERROR(S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);
    }

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
