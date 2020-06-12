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

static int s2n_tls13_conn_copy_server_finished_hash(struct s2n_connection *conn) {
    notnull_check(conn);
    s2n_tls13_connection_keys(keys, conn);
    struct s2n_hash_state hash_state = {0};

    GUARD(s2n_handshake_get_hash_state(conn, keys.hash_algorithm, &hash_state));
    GUARD(s2n_hash_copy(&conn->handshake.server_finished_copy, &hash_state));

    return 0;
}

/* this hook runs after hashes are updated */
int s2n_conn_post_handshake_hashes_update(struct s2n_connection *conn)
{
    notnull_check(conn);

    if (conn->actual_protocol_version < S2N_TLS13) {
        return 0;
    }

    struct s2n_blob client_seq = {.data = conn->secure.client_sequence_number,.size = sizeof(conn->secure.client_sequence_number) };
    struct s2n_blob server_seq = {.data = conn->secure.server_sequence_number,.size = sizeof(conn->secure.server_sequence_number) };

    switch(s2n_conn_get_current_message_type(conn)) {
    case HELLO_RETRY_MSG:
        /* If we are sending a retry request, we didn't decide on a key share. There are no secrets to handle. */
        break;
    case SERVER_HELLO:
        if (s2n_hello_retry_validate(conn) != S2N_SUCCESS) {
            GUARD(s2n_tls13_handle_handshake_secrets(conn));
        }
        GUARD(s2n_blob_zero(&client_seq));
        GUARD(s2n_blob_zero(&server_seq));
        conn->server = &conn->secure;
        conn->client = &conn->secure;
        GUARD(s2n_stuffer_wipe(&conn->alert_in));
        break;
    case SERVER_FINISHED:
        GUARD(s2n_tls13_conn_copy_server_finished_hash(conn));
        break;
    case CLIENT_FINISHED:
        /* Reset sequence numbers for Application Data */
        GUARD(s2n_blob_zero(&client_seq));
        GUARD(s2n_blob_zero(&server_seq));
        break;
    default:
        break;
    }
    return 0;
}

/* this hook runs before hashes are updated */
int s2n_conn_pre_handshake_hashes_update(struct s2n_connection *conn)
{
    notnull_check(conn);

    if (conn->actual_protocol_version < S2N_TLS13) {
        return 0;
    }

    /* Right now this function is only concerned with CLIENT_FINISHED */
    if (s2n_conn_get_current_message_type(conn) != CLIENT_FINISHED) {
        return 0;
    }

    /* This runs before handshake update because application secrets uses only
     * handshake hashes up to Server finished. This handler works in both
     * read and write modes.
     */
    GUARD(s2n_tls13_handle_application_secrets(conn));

    return 0;
}

int s2n_conn_update_handshake_hashes(struct s2n_connection *conn, struct s2n_blob *data)
{
    notnull_check(conn);
    notnull_check(data);

    if (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_MD5)) {
        /* The handshake MD5 hash state will fail the s2n_hash_is_available() check
         * since MD5 is not permitted in FIPS mode. This check will not be used as
         * the handshake MD5 hash state is specifically used by the TLS 1.0 and TLS 1.1
         * PRF, which is required to comply with the TLS 1.0 and 1.1 RFCs and is approved
         * as per NIST Special Publication 800-52 Revision 1.
         */
        GUARD(s2n_hash_update(&conn->handshake.md5, data->data, data->size));
    }

    if (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_SHA1)) {
        GUARD(s2n_hash_update(&conn->handshake.sha1, data->data, data->size));
    }

    const uint8_t md5_sha1_required = (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_MD5) &&
                                       s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_SHA1));

    if (md5_sha1_required) {
        /* The MD5_SHA1 hash can still be used for TLS 1.0 and 1.1 in FIPS mode for 
         * the handshake hashes. This will only be used for the signature check in the
         * CertificateVerify message and the PRF. NIST SP 800-52r1 approves use
         * of MD5_SHA1 for these use cases (see footnotes 15 and 20, and section
         * 3.3.2) */
        GUARD(s2n_hash_update(&conn->handshake.md5_sha1, data->data, data->size));
    }

    if (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_SHA224)) {
        GUARD(s2n_hash_update(&conn->handshake.sha224, data->data, data->size));
    }

    if (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_SHA256)) {
        GUARD(s2n_hash_update(&conn->handshake.sha256, data->data, data->size));
    }

    if (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_SHA384)) {
        GUARD(s2n_hash_update(&conn->handshake.sha384, data->data, data->size));
    }

    if (s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_SHA512)) {
        GUARD(s2n_hash_update(&conn->handshake.sha512, data->data, data->size));
    }

    return 0;
}

/* When a HelloRetryRequest message is used, the hash transcript needs to be recreated.
 * This is done with a synthetic message header, and the hash of ClientHello1.
 *
 * https://tools.ietf.org/html/rfc8446#section-4.4.1
 */
int s2n_server_hello_retry_recreate_transcript(struct s2n_connection *conn)
{
    notnull_check(conn);

    s2n_tls13_connection_keys(keys, conn);
    uint8_t hash_digest_length = keys.size;

    /* Create the MessageHash (our synthetic message) */
    uint8_t msghdr[MESSAGE_HASH_HEADER_LENGTH] = {0};
    msghdr[0] = TLS_MESSAGE_HASH;
    msghdr[MESSAGE_HASH_HEADER_LENGTH - 1] = hash_digest_length;

    /* Grab the current transcript hash to use as the ClientHello1 value. */
    struct s2n_hash_state hash_state, client_hello1_hash;
    uint8_t client_hello1_digest_out[S2N_MAX_DIGEST_LEN];
    GUARD(s2n_handshake_get_hash_state(conn, keys.hash_algorithm, &hash_state));

    GUARD(s2n_hash_new(&client_hello1_hash));
    GUARD(s2n_hash_copy(&client_hello1_hash, &hash_state));
    GUARD(s2n_hash_digest(&client_hello1_hash, client_hello1_digest_out, hash_digest_length));
    GUARD(s2n_hash_free(&client_hello1_hash));

    /* Step 1: Reset the hash state */
    GUARD(s2n_handshake_reset_hash_state(conn, keys.hash_algorithm));

    /* Step 2: Update the transcript with the synthetic message */
    struct s2n_blob msg_blob = {0};
    GUARD(s2n_blob_init(&msg_blob, msghdr, MESSAGE_HASH_HEADER_LENGTH));
    GUARD(s2n_conn_update_handshake_hashes(conn, &msg_blob));

    /* Step 3: Update the transcript with the ClientHello1 hash */
    GUARD(s2n_blob_init(&msg_blob, client_hello1_digest_out, hash_digest_length));
    GUARD(s2n_conn_update_handshake_hashes(conn, &msg_blob));

    return 0;
}

