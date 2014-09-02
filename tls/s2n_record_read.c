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
#include <errno.h>
#include <time.h>

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_record.h"
#include "tls/s2n_crypto.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_cipher.h"
#include "crypto/s2n_hmac.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"
#include "utils/s2n_blob.h"

int s2n_sslv2_record_header_parse(struct s2n_connection *conn, uint8_t *record_type, uint8_t *client_protocol_version, uint16_t *fragment_length, const char **err)
{
    struct s2n_stuffer *in = &conn->header_in;

    if (s2n_stuffer_data_available(in) < S2N_TLS_RECORD_HEADER_LENGTH) {
        *err = "Trying to parse an empty record";
        return -1;
    }

    GUARD(s2n_stuffer_read_uint16(in, fragment_length, err));

    /* Adjust to account for the 3 bytes of payload data we consumed in the header */
    *fragment_length -= 3;

    GUARD(s2n_stuffer_read_uint8(in, record_type, err));

    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    GUARD(s2n_stuffer_read_bytes(in, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN, err));

    *client_protocol_version = (protocol_version[0] * 10) + protocol_version[1];

    return 0;
}

int s2n_record_header_parse(struct s2n_connection *conn, uint8_t *content_type, uint16_t *fragment_length, const char **err)
{
    struct s2n_stuffer *in = &conn->header_in;

    if (s2n_stuffer_data_available(in) < S2N_TLS_RECORD_HEADER_LENGTH) {
        *err = "Trying to parse an empty record";
        return -1;
    }

    GUARD(s2n_stuffer_read_uint8(in, content_type, err));

    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    GUARD(s2n_stuffer_read_bytes(in, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN, err));

    uint8_t version = (protocol_version[0] * 10) + protocol_version[1];

    if (conn->actual_protocol_version_established && conn->actual_protocol_version != version) {
        *err = "Protocol version change attempt detected";
        return -1;
    }

    GUARD(s2n_stuffer_read_uint16(in, fragment_length, err));

    /* Some servers send fragments that are above the maximum length.  (e.g.
     * Openssl 1.0.1, so we don't check if the fragment length is >
     * S2N_TLS_MAXIMUM_FRAGMENT_LENGTH. The on-the-wire max is 65k 
     */

    GUARD(s2n_stuffer_reread(in, err));

    return 0;
}

static int s2n_verify_padding(struct s2n_connection *conn, struct s2n_blob *decrypted, const char **err)
{
    gte_check(decrypted->size, 0);

    uint8_t p = decrypted->data[decrypted->size - 1];

    if (p > (decrypted->size - 1)) {
        *err = "Could not verify fragment";
        return -1;
    }

    /* SSLv3 doesn't specify what the padding should actualy be */
    if (conn->actual_protocol_version == S2N_SSLv3) {
        return 0;
    }

    /* Check all 255 potential padding bytes */
    uint8_t check = 255;
    if (decrypted->size < 255) {
        check = decrypted->size - 1;
    }

    uint8_t run = 0;
    for (int i = decrypted->size - 1 - check; i < decrypted->size - 1; i++) {
        if (decrypted->data[i] == p) {
            run++;
        } else {
            run = 0;
        }
    }

    if (run < p) {
        *err = "Could not verify fragment";
        return -1;
    }

    return 0;
}

int s2n_record_parse(struct s2n_connection *conn, const char **err)
{
    struct s2n_blob iv;
    struct s2n_blob en;
    uint8_t ivpad[16];
    uint8_t content_type;
    uint16_t fragment_length;
    int padding_mac_good = 1;

    uint8_t *sequence_number = conn->client->client_sequence_number;
    struct s2n_hmac_state *mac = &conn->client->client_record_mac;
    struct s2n_session_key *session_key = &conn->client->client_key;
    struct s2n_cipher_suite *cipher_suite = conn->client->cipher_suite;
    uint8_t *implicit_iv = conn->client->client_implicit_iv;

    if (conn->mode == S2N_CLIENT) {
        sequence_number = conn->server->server_sequence_number;
        mac = &conn->server->server_record_mac;
        session_key = &conn->server->server_key;
        cipher_suite = conn->server->cipher_suite;
        implicit_iv = conn->server->server_implicit_iv;
    }

    GUARD(s2n_record_header_parse(conn, &content_type, &fragment_length, err));

    /* Add the header to the HMAC */
    uint8_t *header = s2n_stuffer_raw_read(&conn->header_in, S2N_TLS_RECORD_HEADER_LENGTH, err);
    notnull_check(header);

    uint16_t encrypted_length = fragment_length;
    if (cipher_suite->cipher->type == S2N_CBC) {
        iv.data = implicit_iv;
        iv.size = cipher_suite->cipher->io.cbc.record_iv_size;
        lte_check(cipher_suite->cipher->io.cbc.record_iv_size, S2N_TLS_MAX_IV_LEN);

        /* For TLS >= 1.1 the IV is in the packet */
        if (conn->actual_protocol_version > S2N_TLS10) {
            GUARD(s2n_stuffer_read(&conn->in, &iv, err));
            gte_check(encrypted_length, iv.size);
            encrypted_length -= iv.size;
        }
    }

    en.size = encrypted_length;
    en.data = s2n_stuffer_raw_read(&conn->in, en.size, err);
    notnull_check(en.data);

    /* Decrypt stuff! */
    switch (cipher_suite->cipher->type) {
    case S2N_STREAM:
        if (cipher_suite->cipher->io.stream.decrypt(session_key, &en, &en, err) < 0) {
            return -1;
        }
        break;
    case S2N_CBC:
        /* Check that we have some data to decrypt */
        ne_check(en.size, 0);

        /* ... and that we have a multiple of the block size */
        eq_check(en.size % iv.size,  0);

        /* Copy the last encrypted block to be the next IV */
        memcpy_check(ivpad, en.data + en.size - iv.size, iv.size);
        if (cipher_suite->cipher->io.cbc.decrypt(session_key, &iv, &en, &en, err) < 0) {
            return -1;
        }
        memcpy_check(implicit_iv, ivpad, iv.size);
        break;
    default:
        return -1;
        break;
    }

    uint16_t payload_length = encrypted_length;

    /* Padding */
    if (cipher_suite->cipher->type == S2N_CBC) {
        if (s2n_verify_padding(conn, &en, err) < 0) {
            padding_mac_good = 0;
        }
        uint16_t padding_length = (en.data[en.size - 1] + 1);

        gte_check(payload_length, padding_length);
        payload_length -= padding_length;
    }

    int mac_digest_size = s2n_hmac_digest_size(mac->alg, err);
    gte_check(mac_digest_size, 0);

    gte_check(payload_length, mac_digest_size);
    payload_length -= mac_digest_size;

    /* Update the MAC */
    header[3] = (payload_length >> 8);
    header[4] = payload_length & 0xff;
    GUARD(s2n_hmac_reset(mac, err));
    GUARD(s2n_hmac_update(mac, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN, err));

    if (conn->actual_protocol_version == S2N_SSLv3) {
        GUARD(s2n_hmac_update(mac, header, 1, err));
        GUARD(s2n_hmac_update(mac, header + 3, 2, err));
    } else {
        GUARD(s2n_hmac_update(mac, header, S2N_TLS_RECORD_HEADER_LENGTH, err));
    }
    GUARD(s2n_hmac_update(mac, en.data, payload_length, err));
    s2n_increment_sequence_number(sequence_number);

    /* MAC check */
    uint8_t check_digest[S2N_MAX_DIGEST_LEN];
    lte_check(mac_digest_size, sizeof(check_digest));
    GUARD(s2n_hmac_digest(mac, check_digest, mac_digest_size, err));

    if (s2n_hmac_digest_verify(en.data + payload_length, mac_digest_size, check_digest, mac_digest_size, err) < 0) {
        *err = "Could not verify fragment";
        padding_mac_good = 0;
    }

    /* Either the padding or the MAC were bad, reject the fragment */
    if (!padding_mac_good) {
        GUARD(s2n_stuffer_wipe(&conn->in, err));
        return -1;
    }

    /* O.k., we've successfully read and decrypted the record, now we need to align the stuffer
     * for reading the plaintext data.
     */
    GUARD(s2n_stuffer_reread(&conn->in, err));
    GUARD(s2n_stuffer_reread(&conn->header_in, err));

    /* Skip the IV, if any */
    if (cipher_suite->cipher->type == S2N_CBC && conn->actual_protocol_version > S2N_TLS10) {
        GUARD(s2n_stuffer_skip_read(&conn->in, cipher_suite->cipher->io.cbc.record_iv_size, err));
    }

    /* Truncate and wipe the MAC and any padding */
    GUARD(s2n_stuffer_wipe_n(&conn->in, s2n_stuffer_data_available(&conn->in) - payload_length, err));
    conn->in_status = PLAINTEXT;

    return 0;
}
