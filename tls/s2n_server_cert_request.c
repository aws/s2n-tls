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

#include <s2n.h>

#include "crypto/s2n_certificate.h"
#include "error/s2n_errno.h"
#include "extensions/s2n_server_certificate_request_extensions.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"
#include "tls/s2n_signature_algorithms.h"
#include "tls/s2n_signature_scheme.h"
#include "tls/s2n_tls.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_array.h"

/* RFC's that define below values:
 *  - https://tools.ietf.org/html/rfc5246#section-7.4.4
 *  - https://tools.ietf.org/search/rfc4492#section-5.5
 */
typedef enum {
    S2N_CERT_TYPE_RSA_SIGN = 1,
    S2N_CERT_TYPE_DSS_SIGN = 2,
    S2N_CERT_TYPE_RSA_FIXED_DH = 3,
    S2N_CERT_TYPE_DSS_FIXED_DH = 4,
    S2N_CERT_TYPE_RSA_EPHEMERAL_DH_RESERVED = 5,
    S2N_CERT_TYPE_DSS_EPHEMERAL_DH_RESERVED = 6,
    S2N_CERT_TYPE_FORTEZZA_DMS_RESERVED = 20,
    S2N_CERT_TYPE_ECDSA_SIGN = 64,
    S2N_CERT_TYPE_RSA_FIXED_ECDH = 65,
    S2N_CERT_TYPE_ECDSA_FIXED_ECDH = 66,
} s2n_cert_type;

static uint8_t s2n_cert_type_preference_list[] = {
    S2N_CERT_TYPE_RSA_SIGN,
    S2N_CERT_TYPE_ECDSA_SIGN
};

static int s2n_cert_type_to_pkey_type(s2n_cert_type cert_type_in, s2n_pkey_type *pkey_type_out) {
    switch(cert_type_in) {
        case S2N_CERT_TYPE_RSA_SIGN:
            *pkey_type_out = S2N_PKEY_TYPE_RSA;
            return 0;
        case S2N_CERT_TYPE_ECDSA_SIGN:
            *pkey_type_out = S2N_PKEY_TYPE_ECDSA;
            return 0;
        default:
            S2N_ERROR(S2N_CERT_ERR_TYPE_UNSUPPORTED);
    }
}

static int s2n_recv_client_cert_preferences(struct s2n_stuffer *in, s2n_cert_type *chosen_cert_type_out)
{
    uint8_t cert_types_len;
    GUARD(s2n_stuffer_read_uint8(in, &cert_types_len));

    uint8_t *their_cert_type_pref_list = s2n_stuffer_raw_read(in, cert_types_len);
    notnull_check(their_cert_type_pref_list);

    /* Iterate through our preference list from most to least preferred, and return the first match that we find. */
    for (int our_cert_pref_idx = 0; our_cert_pref_idx < sizeof(s2n_cert_type_preference_list); our_cert_pref_idx++) {
        for (int their_cert_idx = 0; their_cert_idx < cert_types_len; their_cert_idx++) {
            if (their_cert_type_pref_list[their_cert_idx] == s2n_cert_type_preference_list[our_cert_pref_idx]) {
                *chosen_cert_type_out = s2n_cert_type_preference_list[our_cert_pref_idx];
                return 0;
            }
        }
    }

    S2N_ERROR(S2N_ERR_CERT_TYPE_UNSUPPORTED);
}

static int s2n_set_cert_chain_as_client(struct s2n_connection *conn)
{
    if (s2n_config_get_num_default_certs(conn->config) > 0) {
        GUARD(s2n_choose_sig_scheme_from_peer_preference_list(conn, &conn->handshake_params.server_sig_hash_algs,
                                                               &conn->secure.client_cert_sig_scheme));

        struct s2n_cert_chain_and_key *cert = s2n_config_get_single_default_cert(conn->config);
        notnull_check(cert);
        conn->handshake_params.our_chain_and_key = cert;
    }

    return 0;
}

int s2n_tls13_cert_req_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;

    /* read request context length */
    uint8_t request_context_length;
    uint16_t extensions_length;
    GUARD(s2n_stuffer_read_uint8(in, &request_context_length));
    /* RFC 8446: This field SHALL be zero length unless used for the post-handshake authentication */
    S2N_ERROR_IF(request_context_length != 0, S2N_ERR_BAD_MESSAGE);
    GUARD(s2n_stuffer_read_uint16(in, &extensions_length));
    S2N_ERROR_IF(s2n_stuffer_data_available(in) < extensions_length, S2N_ERR_BAD_MESSAGE);

    /* read and parse extensions */
    struct s2n_blob extensions = {0};
    extensions.size = extensions_length;
    extensions.data = s2n_stuffer_raw_read(in, extensions.size);
    notnull_check(extensions.data);

    GUARD(s2n_server_certificate_request_extensions_recv(conn, &extensions));

    return 0;
}

int s2n_cert_req_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;

    s2n_cert_type cert_type = 0;
    GUARD(s2n_recv_client_cert_preferences(in, &cert_type));
    GUARD(s2n_cert_type_to_pkey_type(cert_type, &conn->secure.client_cert_pkey_type));

    if (conn->actual_protocol_version == S2N_TLS12) {
        GUARD(s2n_recv_supported_sig_scheme_list(in, &conn->handshake_params.server_sig_hash_algs));
    }

    uint16_t cert_authorities_len = 0;
    GUARD(s2n_stuffer_read_uint16(in, &cert_authorities_len));

    /* For now we don't parse X.501 encoded CA Distinguished Names.
     * Don't fail just yet as we still may succeed if we provide
     * right certificate or if ClientAuth is optional. */
    GUARD(s2n_stuffer_skip_read(in, cert_authorities_len));

    /* In the future we may have more advanced logic to match a set of configured certificates against
     * The cert authorities extension and the signature algorithms advertised.
     * For now, this will just set the only certificate configured.
     */
    GUARD(s2n_set_cert_chain_as_client(conn));

    return 0;
}

int s2n_tls13_cert_req_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    /* Write 0 length request context https://tools.ietf.org/html/rfc8446#section-4.3.2 */
    GUARD(s2n_stuffer_write_uint8(out, 0));
    /* write total extension length */
    GUARD(s2n_stuffer_write_uint16(out, s2n_server_certificate_request_extensions_size(conn)));
    /* write extensions */
    GUARD(s2n_server_certificate_request_extensions_send(conn, out));

    return 0;
}

int s2n_cert_req_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    uint8_t client_cert_preference_list_size = sizeof(s2n_cert_type_preference_list);
    GUARD(s2n_stuffer_write_uint8(out, client_cert_preference_list_size));

    for (int i = 0; i < client_cert_preference_list_size; i++) {
        GUARD(s2n_stuffer_write_uint8(out, s2n_cert_type_preference_list[i]));
    }

    if (conn->actual_protocol_version == S2N_TLS12) {
        GUARD(s2n_send_supported_sig_scheme_list(conn, out));
    }

    /* RFC 5246 7.4.4 - If the certificate_authorities list is empty, then the
     * client MAY send any certificate of the appropriate ClientCertificateType */
    uint16_t acceptable_cert_authorities_len = 0;
    GUARD(s2n_stuffer_write_uint16(out, acceptable_cert_authorities_len));

    return 0;
}
