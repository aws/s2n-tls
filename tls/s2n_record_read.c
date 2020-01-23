/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <sys/param.h>

#include "crypto/s2n_sequence.h"
#include "crypto/s2n_cipher.h"
#include "crypto/s2n_hmac.h"

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_record_read.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

int s2n_sslv2_record_header_parse(
    struct s2n_connection *conn,
    uint8_t * record_type,
    uint8_t * client_protocol_version,
    uint16_t * fragment_length)
{
    struct s2n_stuffer *in = &conn->header_in;

    S2N_ERROR_IF(s2n_stuffer_data_available(in) < S2N_TLS_RECORD_HEADER_LENGTH, S2N_ERR_BAD_MESSAGE);

    GUARD(s2n_stuffer_read_uint16(in, fragment_length));

    /* Adjust to account for the 3 bytes of payload data we consumed in the header */
    *fragment_length -= 3;

    GUARD(s2n_stuffer_read_uint8(in, record_type));

    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    GUARD(s2n_stuffer_read_bytes(in, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

    *client_protocol_version = (protocol_version[0] * 10) + protocol_version[1];

    return 0;
}

int s2n_record_header_parse(
    struct s2n_connection *conn,
    uint8_t *content_type,
    uint16_t *fragment_length)
{
    struct s2n_stuffer *in = &conn->header_in;

    S2N_ERROR_IF(s2n_stuffer_data_available(in) < S2N_TLS_RECORD_HEADER_LENGTH, S2N_ERR_BAD_MESSAGE);

    GUARD(s2n_stuffer_read_uint8(in, content_type));

    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    GUARD(s2n_stuffer_read_bytes(in, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

    const uint8_t version = (protocol_version[0] * 10) + protocol_version[1];
    /* https://tools.ietf.org/html/rfc5246#appendix-E.1 states that servers must accept any value {03,XX} as the record
     * layer version number for the first TLS record. There is some ambiguity here because the client does not know
     * what version to use in the record header prior to receiving the ServerHello. Some client implementations may use
     * a garbage value(not {03,XX}) in the ClientHello.
     * Choose to be lenient to these clients. After protocol negotiation, we will enforce that all record versions
     * match the negotiated version.
     */

    S2N_ERROR_IF(conn->actual_protocol_version_established &&
        MIN(conn->actual_protocol_version, S2N_TLS12) /* check against legacy record version (1.2) in tls 1.3 */
        != version, S2N_ERR_BAD_MESSAGE);
    GUARD(s2n_stuffer_read_uint16(in, fragment_length));

    /* Some servers send fragments that are above the maximum length.  (e.g.
     * Openssl 1.0.1, so we don't check if the fragment length is >
     * S2N_TLS_MAXIMUM_FRAGMENT_LENGTH. The on-the-wire max is 65k
     */
    GUARD(s2n_stuffer_reread(in));

    return 0;
}

int s2n_record_parse(struct s2n_connection *conn)
{
    uint8_t content_type;
    uint16_t encrypted_length;
    GUARD(s2n_record_header_parse(conn, &content_type, &encrypted_length));

    /* In TLS 1.3, handle CCS message as unprotected records */
    struct s2n_crypto_parameters *current_client_crypto = conn->client;
    struct s2n_crypto_parameters *current_server_crypto = conn->server;
    if (conn->actual_protocol_version == S2N_TLS13 && content_type == TLS_CHANGE_CIPHER_SPEC) {
        conn->client = &conn->initial;
        conn->server = &conn->initial;
    }

    const struct s2n_cipher_suite *cipher_suite = conn->client->cipher_suite;
    uint8_t *implicit_iv = conn->client->client_implicit_iv;
    struct s2n_hmac_state *mac = &conn->client->client_record_mac;
    uint8_t *sequence_number = conn->client->client_sequence_number;
    struct s2n_session_key *session_key = &conn->client->client_key;

    if (conn->mode == S2N_CLIENT) {
        cipher_suite = conn->server->cipher_suite;
        implicit_iv = conn->server->server_implicit_iv;
        mac = &conn->server->server_record_mac;
        sequence_number = conn->server->server_sequence_number;
        session_key = &conn->server->server_key;
    }

    if (conn->actual_protocol_version == S2N_TLS13 && content_type == TLS_CHANGE_CIPHER_SPEC) {
        conn->client = current_client_crypto;
        conn->server = current_server_crypto;
    }

    switch (cipher_suite->record_alg->cipher->type) {
    case S2N_AEAD:
        GUARD(s2n_record_parse_aead(cipher_suite, conn, content_type, encrypted_length, implicit_iv, mac, sequence_number, session_key));
        break;
    case S2N_CBC:
        GUARD(s2n_record_parse_cbc(cipher_suite, conn, content_type, encrypted_length, implicit_iv, mac, sequence_number, session_key));
        break;
    case S2N_COMPOSITE:
        GUARD(s2n_record_parse_composite(cipher_suite, conn, content_type, encrypted_length, implicit_iv, mac, sequence_number, session_key));
        break;
    case S2N_STREAM:
        GUARD(s2n_record_parse_stream(cipher_suite, conn, content_type, encrypted_length, implicit_iv, mac, sequence_number, session_key));
        break;
    default:
        S2N_ERROR(S2N_ERR_CIPHER_TYPE);
        break;
    }

    return 0;
}

int s2n_parse_record_type(struct s2n_stuffer *stuffer, uint8_t * record_type) 
{
    GUARD(s2n_stuffer_skip_read(stuffer, s2n_stuffer_data_available(stuffer) - 1));

    /* set the true record type */
    GUARD(s2n_stuffer_read_uint8(stuffer, record_type));

    /* wipe this last byte so the rest handshake works like < TLS 1.3 */
    GUARD(s2n_stuffer_wipe_n(stuffer, 1));

    /* set the read cursor at where it should be */
    GUARD(s2n_stuffer_reread(stuffer));

    return 0;
}

