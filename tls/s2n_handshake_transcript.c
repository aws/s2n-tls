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

#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13_handshake.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_blob.h"

/* Length of the synthetic message header */
#define MESSAGE_HASH_HEADER_LENGTH  4

static S2N_RESULT s2n_tls13_calculate_digest(struct s2n_connection *conn, uint8_t *digest) {
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(digest);

    s2n_hash_algorithm hash_algorithm = S2N_HASH_NONE;
    RESULT_ENSURE_REF(conn->secure.cipher_suite);
    RESULT_GUARD_POSIX(s2n_hmac_hash_alg(conn->secure.cipher_suite->prf_alg, &hash_algorithm));

    uint8_t digest_size = 0;
    RESULT_GUARD_POSIX(s2n_hash_digest_size(hash_algorithm, &digest_size));

    RESULT_ENSURE_REF(conn->handshake.hashes);
    struct s2n_hash_state *hash_state = &conn->handshake.hashes->hash_workspace;
    RESULT_GUARD(s2n_handshake_copy_hash_state(conn, hash_algorithm, hash_state));
    RESULT_GUARD_POSIX(s2n_hash_digest(hash_state, digest, digest_size));
    return S2N_RESULT_OK;
}

int s2n_conn_update_handshake_hashes(struct s2n_connection *conn, struct s2n_blob *data)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(data);
    struct s2n_handshake_hashes *hashes = conn->handshake.hashes;
    POSIX_ENSURE_REF(hashes);

    if (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_MD5)) {
        /* The handshake MD5 hash state will fail the s2n_hash_is_available() check
         * since MD5 is not permitted in FIPS mode. This check will not be used as
         * the handshake MD5 hash state is specifically used by the TLS 1.0 and TLS 1.1
         * PRF, which is required to comply with the TLS 1.0 and 1.1 RFCs and is approved
         * as per NIST Special Publication 800-52 Revision 1.
         */
        POSIX_GUARD(s2n_hash_update(&hashes->md5, data->data, data->size));
    }

    if (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_SHA1)) {
        POSIX_GUARD(s2n_hash_update(&hashes->sha1, data->data, data->size));
    }

    const uint8_t md5_sha1_required = (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_MD5) &&
                                       s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_SHA1));

    if (md5_sha1_required) {
        /* The MD5_SHA1 hash can still be used for TLS 1.0 and 1.1 in FIPS mode for 
         * the handshake hashes. This will only be used for the signature check in the
         * CertificateVerify message and the PRF. NIST SP 800-52r1 approves use
         * of MD5_SHA1 for these use cases (see footnotes 15 and 20, and section
         * 3.3.2) */
        POSIX_GUARD(s2n_hash_update(&hashes->md5_sha1, data->data, data->size));
    }

    if (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_SHA224)) {
        POSIX_GUARD(s2n_hash_update(&hashes->sha224, data->data, data->size));
    }

    if (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_SHA256)) {
        POSIX_GUARD(s2n_hash_update(&hashes->sha256, data->data, data->size));
    }

    if (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_SHA384)) {
        POSIX_GUARD(s2n_hash_update(&hashes->sha384, data->data, data->size));
    }

    if (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_SHA512)) {
        POSIX_GUARD(s2n_hash_update(&hashes->sha512, data->data, data->size));
    }

    /*
     * TLS1.3 secret derivation requires specific transcript hash digests as inputs.
     * Save the relevant hash state digests for later use.
     */
    if (s2n_connection_get_protocol_version(conn) >= S2N_TLS13) {
        switch(s2n_conn_get_current_message_type(conn)) {
            case CLIENT_HELLO:
                POSIX_ENSURE_REF(conn->secure.cipher_suite);
                if (conn->secure.cipher_suite->prf_alg != S2N_HMAC_NONE) {
                    POSIX_GUARD_RESULT(s2n_tls13_calculate_digest(conn, hashes->client_hello_digest));
                }
                break;
            case SERVER_HELLO:
                POSIX_GUARD_RESULT(s2n_tls13_calculate_digest(conn, hashes->server_hello_digest));
                break;
            case SERVER_FINISHED:
                POSIX_GUARD_RESULT(s2n_tls13_calculate_digest(conn, hashes->server_finished_digest));
                break;
            case CLIENT_FINISHED:
                POSIX_GUARD_RESULT(s2n_tls13_calculate_digest(conn, hashes->client_finished_digest));
                break;
            default:
                break;
        }
    }

    return S2N_SUCCESS;
}

/* When a HelloRetryRequest message is used, the hash transcript needs to be recreated.
 * This is done with a synthetic message header, and the hash of ClientHello1.
 *
 * https://tools.ietf.org/html/rfc8446#section-4.4.1
 */
int s2n_server_hello_retry_recreate_transcript(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    struct s2n_handshake_hashes *hashes = conn->handshake.hashes;
    POSIX_ENSURE_REF(hashes);

    s2n_tls13_connection_keys(keys, conn);
    uint8_t hash_digest_length = keys.size;

    /* Create the MessageHash (our synthetic message) */
    uint8_t msghdr[MESSAGE_HASH_HEADER_LENGTH] = {0};
    msghdr[0] = TLS_MESSAGE_HASH;
    msghdr[MESSAGE_HASH_HEADER_LENGTH - 1] = hash_digest_length;

    /* Grab the current transcript hash to use as the ClientHello1 value. */
    struct s2n_hash_state *client_hello1_hash = &hashes->hash_workspace;
    uint8_t client_hello1_digest_out[S2N_MAX_DIGEST_LEN] = { 0 };
    POSIX_GUARD_RESULT(s2n_handshake_copy_hash_state(conn, keys.hash_algorithm, client_hello1_hash));
    POSIX_GUARD(s2n_hash_digest(client_hello1_hash, client_hello1_digest_out, hash_digest_length));

    /* Step 1: Reset the hash state */
    POSIX_GUARD_RESULT(s2n_handshake_reset_hash_state(conn, keys.hash_algorithm));

    /* Step 2: Update the transcript with the synthetic message */
    struct s2n_blob msg_blob = {0};
    POSIX_GUARD(s2n_blob_init(&msg_blob, msghdr, MESSAGE_HASH_HEADER_LENGTH));
    POSIX_GUARD(s2n_conn_update_handshake_hashes(conn, &msg_blob));

    /* Step 3: Update the transcript with the ClientHello1 hash */
    POSIX_GUARD(s2n_blob_init(&msg_blob, client_hello1_digest_out, hash_digest_length));
    POSIX_GUARD(s2n_conn_update_handshake_hashes(conn, &msg_blob));

    return S2N_SUCCESS;
}
