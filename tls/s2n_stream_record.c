/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <sys/param.h>
#include <errno.h>
#include <time.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_record.h"
#include "tls/s2n_crypto.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_sequence.h"
#include "crypto/s2n_cipher.h"
#include "crypto/s2n_hmac.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"
#include "utils/s2n_blob.h"

int s2n_stream_record_parse(struct s2n_connection *conn)
{
    struct s2n_blob en;
    uint8_t content_type;
    uint16_t encrypted_length;

    uint8_t *sequence_number = conn->client->client_sequence_number;
    struct s2n_hmac_state *mac = &conn->client->client_record_mac;
    struct s2n_session_key *session_key = &conn->client->client_key;
    const struct s2n_cipher *cipher = conn->client->cipher_suite->record_alg->cipher;

    if (conn->mode == S2N_CLIENT) {
        sequence_number = conn->server->server_sequence_number;
        mac = &conn->server->server_record_mac;
        session_key = &conn->server->server_key;
        cipher = conn->server->cipher_suite->record_alg->cipher;
    }

    GUARD(s2n_record_header_parse(conn, &content_type, &encrypted_length));

    /* Add the header to the HMAC */
    uint8_t *header = s2n_stuffer_raw_read(&conn->header_in, S2N_TLS_RECORD_HEADER_LENGTH);
    notnull_check(header);

    en.size = encrypted_length;
    en.data = s2n_stuffer_raw_read(&conn->in, en.size);
    notnull_check(en.data);

    uint16_t payload_length = encrypted_length;
    uint8_t mac_digest_size;
    GUARD(s2n_hmac_digest_size(mac->alg, &mac_digest_size));

    gte_check(payload_length, mac_digest_size);
    payload_length -= mac_digest_size;

    /* Decrypt stuff! */
    GUARD(cipher->io.stream.decrypt(session_key, &en, &en));

    /* Update the MAC */
    header[3] = (payload_length >> 8);
    header[4] = payload_length & 0xff;
    GUARD(s2n_hmac_reset(mac));
    GUARD(s2n_hmac_update(mac, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));

    if (conn->actual_protocol_version == S2N_SSLv3) {
        GUARD(s2n_hmac_update(mac, header, 1));
        GUARD(s2n_hmac_update(mac, header + 3, 2));
    } else {
        GUARD(s2n_hmac_update(mac, header, S2N_TLS_RECORD_HEADER_LENGTH));
    }

    struct s2n_blob seq = {.data = sequence_number,.size = S2N_TLS_SEQUENCE_NUM_LEN };
    GUARD(s2n_increment_sequence_number(&seq));

    /* MAC check for streaming ciphers - no padding */
    GUARD(s2n_hmac_update(mac, en.data, payload_length));

    uint8_t check_digest[S2N_MAX_DIGEST_LEN];
    lte_check(mac_digest_size, sizeof(check_digest));
    GUARD(s2n_hmac_digest(mac, check_digest, mac_digest_size));

    if (s2n_hmac_digest_verify(en.data + payload_length, check_digest, mac_digest_size) < 0) {
        GUARD(s2n_stuffer_wipe(&conn->in));
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    /* Align the stuffer for reading the plaintext data. */
    GUARD(s2n_stuffer_reread(&conn->in));
    GUARD(s2n_stuffer_reread(&conn->header_in));

    /* Truncate and wipe the MAC and any padding */
    GUARD(s2n_stuffer_wipe_n(&conn->in, s2n_stuffer_data_available(&conn->in) - payload_length));
    conn->in_status = PLAINTEXT;

    return 0;
}

int s2n_stream_record_write(struct s2n_connection *conn, uint8_t content_type, struct s2n_blob *in)
{
    struct s2n_blob out, en;
    uint8_t padding = 0;
    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    uint8_t *sequence_number = conn->server->server_sequence_number;
    struct s2n_hmac_state *mac = &conn->server->server_record_mac;
    struct s2n_session_key *session_key = &conn->server->server_key;
    const struct s2n_cipher *cipher = conn->server->cipher_suite->record_alg->cipher;

    if (conn->mode == S2N_CLIENT) {
        sequence_number = conn->client->client_sequence_number;
        mac = &conn->client->client_record_mac;
        session_key = &conn->client->client_key;
        cipher = conn->client->cipher_suite->record_alg->cipher;
    }

    if (s2n_stuffer_data_available(&conn->out)) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    uint8_t mac_digest_size;
    GUARD(s2n_hmac_digest_size(mac->alg, &mac_digest_size));

    /* Figure out what the length of the fragment. */
    uint16_t data_bytes_to_take = MIN(in->size, s2n_record_max_write_payload_size(conn));

    uint16_t extra = s2n_record_overhead(conn);

    /* Start the MAC with the sequence number */
    GUARD(s2n_hmac_update(mac, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));

    /* Now that we know the length, start writing the record */
    protocol_version[0] = conn->actual_protocol_version / 10;
    protocol_version[1] = conn->actual_protocol_version % 10;
    GUARD(s2n_stuffer_write_uint8(&conn->out, content_type));
    GUARD(s2n_stuffer_write_bytes(&conn->out, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

    /* First write a header that has the payload length, this is for the MAC */
    GUARD(s2n_stuffer_write_uint16(&conn->out, data_bytes_to_take));

    if (conn->actual_protocol_version > S2N_SSLv3) {
        GUARD(s2n_hmac_update(mac, conn->out.blob.data, S2N_TLS_RECORD_HEADER_LENGTH));
    } else {
        /* SSLv3 doesn't include the protocol version in the MAC */
        GUARD(s2n_hmac_update(mac, conn->out.blob.data, 1));
        GUARD(s2n_hmac_update(mac, conn->out.blob.data + 3, 2));
    }

    /* Rewrite the length to be the actual fragment length */
    uint16_t actual_fragment_length = data_bytes_to_take + padding + extra;
    GUARD(s2n_stuffer_wipe_n(&conn->out, 2));
    GUARD(s2n_stuffer_write_uint16(&conn->out, actual_fragment_length));

    /* We are done with this sequence number, so we can increment it */
    struct s2n_blob seq = {.data = sequence_number,.size = S2N_TLS_SEQUENCE_NUM_LEN };
    GUARD(s2n_increment_sequence_number(&seq));

    /* Write the plaintext data */
    out.data = in->data;
    out.size = data_bytes_to_take;
    GUARD(s2n_stuffer_write(&conn->out, &out));
    GUARD(s2n_hmac_update(mac, out.data, out.size));

    /* Write the digest */
    uint8_t *digest = s2n_stuffer_raw_write(&conn->out, mac_digest_size);
    notnull_check(digest);
    GUARD(s2n_hmac_digest(mac, digest, mac_digest_size));
    GUARD(s2n_hmac_reset(mac));

    /* Rewind to rewrite/encrypt the packet */
    GUARD(s2n_stuffer_rewrite(&conn->out));

    /* Skip the header */
    GUARD(s2n_stuffer_skip_write(&conn->out, S2N_TLS_RECORD_HEADER_LENGTH));

    /* Do the encryption */
    en.size = data_bytes_to_take + mac_digest_size;
    en.data = s2n_stuffer_raw_write(&conn->out, en.size);
    notnull_check(en.data);

    GUARD(cipher->io.stream.encrypt(session_key, &en, &en));

    conn->wire_bytes_out += actual_fragment_length + S2N_TLS_RECORD_HEADER_LENGTH;
    return data_bytes_to_take;
}

