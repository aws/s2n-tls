/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "error/s2n_errno.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_record.h"
#include "tls/s2n_cipher_suites.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

int s2n_handshake_write_header(struct s2n_connection *conn, uint8_t message_type)
{
    S2N_ERROR_IF(s2n_stuffer_data_available(&conn->handshake.io), S2N_ERR_HANDSHAKE_STATE);

    /* Write the message header */
    GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, message_type));

    /* Leave the length blank for now */
    uint16_t length = 0;
    GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, length));

    return 0;
}

int s2n_handshake_finish_header(struct s2n_connection *conn)
{
    uint16_t length = s2n_stuffer_data_available(&conn->handshake.io);
    S2N_ERROR_IF(length < TLS_HANDSHAKE_HEADER_LENGTH, S2N_ERR_SIZE_MISMATCH);

    uint16_t payload = length - TLS_HANDSHAKE_HEADER_LENGTH;

    /* Write the message header */
    GUARD(s2n_stuffer_rewrite(&conn->handshake.io));
    GUARD(s2n_stuffer_skip_write(&conn->handshake.io, 1));
    GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, payload));
    GUARD(s2n_stuffer_skip_write(&conn->handshake.io, payload));

    return 0;
}

int s2n_handshake_parse_header(struct s2n_connection *conn, uint8_t * message_type, uint32_t * length)
{
    S2N_ERROR_IF(s2n_stuffer_data_available(&conn->handshake.io) < TLS_HANDSHAKE_HEADER_LENGTH, S2N_ERR_SIZE_MISMATCH);

    /* read the message header */
    GUARD(s2n_stuffer_read_uint8(&conn->handshake.io, message_type));
    GUARD(s2n_stuffer_read_uint24(&conn->handshake.io, length));

    return 0;
}

int s2n_handshake_get_hash_state(struct s2n_connection *conn, s2n_hash_algorithm hash_alg, struct s2n_hash_state *hash_state)
{
    switch (hash_alg) {
    case S2N_HASH_MD5:
        *hash_state = conn->handshake.md5;
        break;
    case S2N_HASH_SHA1:
        *hash_state = conn->handshake.sha1;
        break;
    case S2N_HASH_SHA224:
        *hash_state = conn->handshake.sha224;
        break;
    case S2N_HASH_SHA256:
        *hash_state = conn->handshake.sha256;
        break;
    case S2N_HASH_SHA384:
        *hash_state = conn->handshake.sha384;
        break;
    case S2N_HASH_SHA512:
        *hash_state = conn->handshake.sha512;
        break;
    case S2N_HASH_MD5_SHA1:
        *hash_state = conn->handshake.md5_sha1;
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }
    return 0;
}

int s2n_handshake_require_all_hashes(struct s2n_handshake *handshake)
{
    memset(handshake->required_hash_algs, 1, sizeof(handshake->required_hash_algs));
    return 0;
}

static int s2n_handshake_require_hash(struct s2n_handshake *handshake, s2n_hash_algorithm hash_alg)
{
    handshake->required_hash_algs[hash_alg] = 1;
    return 0;
}

uint8_t s2n_handshake_is_hash_required(struct s2n_handshake *handshake, s2n_hash_algorithm hash_alg)
{
    return handshake->required_hash_algs[hash_alg];
}

/* Update the required handshake hash algs depending on current handshake session state.
 * This function must called at the end of a handshake message handler. Additionally it must be called after the
 * ClientHello or ServerHello is processed in client and server mode respectively. The relevant handshake parameters
 * are not available until those messages are processed.
 */
int s2n_conn_update_required_handshake_hashes(struct s2n_connection *conn)
{
    /* Clear all of the required hashes */
    memset(conn->handshake.required_hash_algs, 0, sizeof(conn->handshake.required_hash_algs));

    message_type_t handshake_message = s2n_conn_get_current_message_type(conn);
    const uint8_t client_cert_verify_done = (handshake_message >= CLIENT_CERT_VERIFY) ? 1 : 0;
    s2n_cert_auth_type client_cert_auth_type;
    GUARD(s2n_connection_get_client_auth_type(conn, &client_cert_auth_type));

    /* If client authentication is possible, all hashes are needed until we're past CLIENT_CERT_VERIFY. */
    if ((client_cert_auth_type != S2N_CERT_AUTH_NONE) && !client_cert_verify_done) {
        GUARD(s2n_handshake_require_all_hashes(&conn->handshake));
        return 0;
    }

    /* We don't need all of the hashes. Set the hash alg(s) required for the PRF */
    switch (conn->actual_protocol_version) {
    case S2N_SSLv3:
    case S2N_TLS10:
    case S2N_TLS11:
        GUARD(s2n_handshake_require_hash(&conn->handshake, S2N_HASH_MD5));
        GUARD(s2n_handshake_require_hash(&conn->handshake, S2N_HASH_SHA1));
        break;
    case S2N_TLS12:
    {
        /* For TLS 1.2 the cipher suite defines the PRF hash alg */
        s2n_hmac_algorithm tls12_prf_alg = conn->secure.cipher_suite->tls12_prf_alg;
        s2n_hash_algorithm hash_alg;
        GUARD(s2n_hmac_hash_alg(tls12_prf_alg, &hash_alg));
        GUARD(s2n_handshake_require_hash(&conn->handshake, hash_alg));
        break;
    }
    }

    return 0;
}

int s2n_conn_find_name_matching_certs(struct s2n_connection *conn)
{
    const char *name = conn->server_name;
    struct s2n_array *certs = conn->config->cert_and_key_pairs;
    for (int i = 0; i < s2n_array_num_elements(certs); i++) {
        struct s2n_cert_chain_and_key *chain_and_key = *((struct s2n_cert_chain_and_key**) s2n_array_get(certs, i));
        s2n_authentication_method auth_method = s2n_cert_chain_and_key_get_auth_method(chain_and_key);
        if (s2n_cert_chain_and_key_matches_name(chain_and_key, name) &&
                !conn->handshake_params.sni_matching_certs[auth_method]) {
            conn->handshake_params.sni_matching_certs[auth_method] = chain_and_key;
            conn->handshake_params.sni_match_exists = 1;
        }
    }

    return 0;
}
