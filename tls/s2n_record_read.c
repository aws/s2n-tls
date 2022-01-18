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

    POSIX_GUARD(s2n_stuffer_read_uint16(in, fragment_length));

    /* Adjust to account for the 3 bytes of payload data we consumed in the header */
    POSIX_ENSURE_GTE(*fragment_length, 3);
    *fragment_length -= 3;

    POSIX_GUARD(s2n_stuffer_read_uint8(in, record_type));

    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    POSIX_GUARD(s2n_stuffer_read_bytes(in, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

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

    POSIX_GUARD(s2n_stuffer_read_uint8(in, content_type));

    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    POSIX_GUARD(s2n_stuffer_read_bytes(in, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

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
    POSIX_GUARD(s2n_stuffer_read_uint16(in, fragment_length));

    /* Some servers send fragments that are above the maximum length.  (e.g.
     * Openssl 1.0.1, so we don't check if the fragment length is >
     * S2N_TLS_MAXIMUM_FRAGMENT_LENGTH. The on-the-wire max is 65k
     */
    POSIX_GUARD(s2n_stuffer_reread(in));

    return 0;
}

/* In TLS 1.3, handle CCS message as unprotected records all the time.
 * https://tools.ietf.org/html/rfc8446#section-5
 *
 * In TLS 1.2 and TLS 1.3 Alert messages are plaintext or encrypted
 * depending on the context of the connection. If we receive an encrypted
 * alert, the record type is TLS_APPLICATION_DATA at this point. It will
 * be decrypted and processed in s2n_handshake_io. We may receive a
 * plaintext alert if we hit an error before the handshake completed
 * (like a certificate failed to validate).
 * https://tools.ietf.org/html/rfc8446#section-6
 *
 * This function is specific to TLS 1.3 to avoid changing the behavior
 * of existing interpretation of TLS 1.2 alerts. */
static bool s2n_is_tls13_plaintext_content(struct s2n_connection *conn, uint8_t content_type)
{
    return conn->actual_protocol_version == S2N_TLS13 && (content_type == TLS_ALERT || content_type == TLS_CHANGE_CIPHER_SPEC);
}

int s2n_record_parse(struct s2n_connection *conn)
{
    uint8_t content_type;
    uint16_t encrypted_length;
    POSIX_GUARD(s2n_record_header_parse(conn, &content_type, &encrypted_length));

    struct s2n_crypto_parameters *current_client_crypto = conn->client;
    struct s2n_crypto_parameters *current_server_crypto = conn->server;
    if (s2n_is_tls13_plaintext_content(conn, content_type)) {
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

    if (s2n_is_tls13_plaintext_content(conn, content_type)) {
        conn->client = current_client_crypto;
        conn->server = current_server_crypto;
    }

    /* The NULL stream cipher MUST NEVER be used for ApplicationData.
     * If ApplicationData is unencrypted, we can't trust it. */
    if (cipher_suite->record_alg->cipher == &s2n_null_cipher) {
        POSIX_ENSURE(content_type != TLS_APPLICATION_DATA, S2N_ERR_DECRYPT);
    }

    switch (cipher_suite->record_alg->cipher->type) {
    case S2N_AEAD:
        POSIX_GUARD(s2n_record_parse_aead(cipher_suite, conn, content_type, encrypted_length, implicit_iv, mac, sequence_number, session_key));
        break;
    case S2N_CBC:
        POSIX_GUARD(s2n_record_parse_cbc(cipher_suite, conn, content_type, encrypted_length, implicit_iv, mac, sequence_number, session_key));
        break;
    case S2N_COMPOSITE:
        POSIX_GUARD(s2n_record_parse_composite(cipher_suite, conn, content_type, encrypted_length, implicit_iv, mac, sequence_number, session_key));
        break;
    case S2N_STREAM:
        POSIX_GUARD(s2n_record_parse_stream(cipher_suite, conn, content_type, encrypted_length, implicit_iv, mac, sequence_number, session_key));
        break;
    default:
        POSIX_BAIL(S2N_ERR_CIPHER_TYPE);
        break;
    }

    return 0;
}

int s2n_tls13_parse_record_type(struct s2n_stuffer *stuffer, uint8_t *record_type)
{
    uint32_t bytes_left = s2n_stuffer_data_available(stuffer);

    /* From rfc8446 Section 5.4
     * The presence of padding does not change the overall record size
     * limitations: the full encoded TLSInnerPlaintext MUST NOT exceed 2^14
     * + 1 octets
     *
     * Certain versions of Java can generate inner plaintexts with lengths up to
     * S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH + 16 (See JDK-8221253)
     * However, after the padding is stripped, the result will always be no more than
     * S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH - 1
     */
    S2N_ERROR_IF(bytes_left > S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH + 16, S2N_ERR_MAX_INNER_PLAINTEXT_SIZE);

    /* set cursor to the end of the stuffer */
    POSIX_GUARD(s2n_stuffer_skip_read(stuffer, bytes_left));

    /* Record type should have values greater than zero.
     * If zero, treat as padding, keep reading and wiping from the back
     * until a non-zero value is found
     */
    *record_type = 0;
    while (*record_type == 0) {
        /* back the cursor by one to read off the last byte */
        POSIX_GUARD(s2n_stuffer_rewind_read(stuffer, 1));

        /* set the record type */
        POSIX_GUARD(s2n_stuffer_read_uint8(stuffer, record_type));

        /* wipe the last byte at the end of the stuffer */
        POSIX_GUARD(s2n_stuffer_wipe_n(stuffer, 1));
    }

    /* only the original plaintext should remain */
    /* now reset the read cursor at where it should be */
    POSIX_GUARD(s2n_stuffer_reread(stuffer));

    /* Even in the incorrect case above with up to 16 extra bytes, we should never see too much data after unpadding */
    S2N_ERROR_IF(s2n_stuffer_data_available(stuffer) > S2N_MAXIMUM_INNER_PLAINTEXT_LENGTH - 1, S2N_ERR_MAX_INNER_PLAINTEXT_SIZE);

    return 0;
}
