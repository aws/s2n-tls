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

int s2n_sslv2_record_header_parse(struct s2n_connection *conn, uint8_t * record_type, uint8_t * client_protocol_version, uint16_t * fragment_length)
{
    struct s2n_stuffer *in = &conn->header_in;

    if (s2n_stuffer_data_available(in) < S2N_TLS_RECORD_HEADER_LENGTH) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    GUARD(s2n_stuffer_read_uint16(in, fragment_length));

    /* Adjust to account for the 3 bytes of payload data we consumed in the header */
    *fragment_length -= 3;

    GUARD(s2n_stuffer_read_uint8(in, record_type));

    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    GUARD(s2n_stuffer_read_bytes(in, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

    *client_protocol_version = (protocol_version[0] * 10) + protocol_version[1];

    return 0;
}

int s2n_record_header_parse(struct s2n_connection *conn, uint8_t * content_type, uint16_t * fragment_length)
{
    struct s2n_stuffer *in = &conn->header_in;

    if (s2n_stuffer_data_available(in) < S2N_TLS_RECORD_HEADER_LENGTH) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    GUARD(s2n_stuffer_read_uint8(in, content_type));

    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    GUARD(s2n_stuffer_read_bytes(in, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

    uint8_t version = (protocol_version[0] * 10) + protocol_version[1];

    if (conn->actual_protocol_version_established && conn->actual_protocol_version != version) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

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
    struct s2n_blob iv;
    struct s2n_blob en;
    struct s2n_blob aad;
    uint8_t content_type;
    uint16_t fragment_length;
    uint8_t ivpad[S2N_TLS_MAX_IV_LEN];
    uint8_t aad_gen[S2N_TLS_MAX_AAD_LEN] = { 0 };
    uint8_t aad_iv[S2N_TLS_MAX_IV_LEN] = { 0 };

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

    GUARD(s2n_record_header_parse(conn, &content_type, &fragment_length));

    /* Add the header to the HMAC */
    uint8_t *header = s2n_stuffer_raw_read(&conn->header_in, S2N_TLS_RECORD_HEADER_LENGTH);
    notnull_check(header);

    uint16_t encrypted_length = fragment_length;
    if (cipher_suite->record_alg->cipher->type == S2N_CBC) {
        iv.data = implicit_iv;
        iv.size = cipher_suite->record_alg->cipher->io.cbc.record_iv_size;
        lte_check(cipher_suite->record_alg->cipher->io.cbc.record_iv_size, S2N_TLS_MAX_IV_LEN);

        /* For TLS >= 1.1 the IV is in the packet */
        if (conn->actual_protocol_version > S2N_TLS10) {
            GUARD(s2n_stuffer_read(&conn->in, &iv));
            gte_check(encrypted_length, iv.size);
            encrypted_length -= iv.size;
        }
    } else if (cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        /* Don't reduce encrypted length for explicit IV, composite decrypt expects it */
        iv.data = implicit_iv;
        iv.size = cipher_suite->record_alg->cipher->io.comp.record_iv_size;
    }

    en.size = encrypted_length;
    en.data = s2n_stuffer_raw_read(&conn->in, en.size);
    notnull_check(en.data);

    uint16_t payload_length = encrypted_length;
    uint8_t mac_digest_size;
    GUARD(s2n_hmac_digest_size(mac->alg, &mac_digest_size));

    gte_check(payload_length, mac_digest_size);
    payload_length -= mac_digest_size;

    /* Compute non-payload parts of the MAC(seq num, type, proto vers, fragment length) for composite ciphers.
     * Composite "decrypt" will MAC the actual payload data.
     */
    if (cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        /* In the decrypt case, this outputs the MAC digest length:
         * https://github.com/openssl/openssl/blob/master/crypto/evp/e_aes_cbc_hmac_sha1.c#L842 */
        int mac_size;
        GUARD(cipher_suite->record_alg->cipher->io.comp.initial_hmac(session_key, sequence_number, content_type, conn->actual_protocol_version,
                                                         payload_length, &mac_size));

        payload_length -= mac_size;
        /* Adjust payload_length for explicit IV */
        if (conn->actual_protocol_version > S2N_TLS10) {
            payload_length -= cipher_suite->record_alg->cipher->io.comp.record_iv_size;
        }
    }

    /* In AEAD mode, the explicit IV is in the record */
    if (cipher_suite->record_alg->cipher->type == S2N_AEAD) {
        gte_check(en.size, cipher_suite->record_alg->cipher->io.aead.record_iv_size);

        struct s2n_stuffer iv_stuffer;
        iv.data = aad_iv;
        iv.size = sizeof(aad_iv);

        GUARD(s2n_stuffer_init(&iv_stuffer, &iv));
        GUARD(s2n_stuffer_write_bytes(&iv_stuffer, implicit_iv, cipher_suite->record_alg->cipher->io.aead.fixed_iv_size));
        GUARD(s2n_stuffer_write_bytes(&iv_stuffer, en.data, cipher_suite->record_alg->cipher->io.aead.record_iv_size));

        /* Set the IV size to the amount of data written */
        iv.size = s2n_stuffer_data_available(&iv_stuffer);

        aad.data = aad_gen;
        aad.size = sizeof(aad_gen);

        /* remove the AEAD overhead from the record size */
        gte_check(payload_length, cipher_suite->record_alg->cipher->io.aead.record_iv_size + cipher_suite->record_alg->cipher->io.aead.tag_size);
        payload_length -= cipher_suite->record_alg->cipher->io.aead.record_iv_size;
        payload_length -= cipher_suite->record_alg->cipher->io.aead.tag_size;

        struct s2n_stuffer ad_stuffer;
        GUARD(s2n_stuffer_init(&ad_stuffer, &aad));
        GUARD(s2n_aead_aad_init(conn, sequence_number, content_type, payload_length, &ad_stuffer));
    }

    /* Decrypt stuff! */
    switch (cipher_suite->record_alg->cipher->type) {
    case S2N_STREAM:
        GUARD(cipher_suite->record_alg->cipher->io.stream.decrypt(session_key, &en, &en));
        break;
    case S2N_CBC:
        /* Check that we have some data to decrypt */
        ne_check(en.size, 0);

        /* ... and that we have a multiple of the block size */
        eq_check(en.size % iv.size, 0);

        /* Copy the last encrypted block to be the next IV */
        if (conn->actual_protocol_version < S2N_TLS11) {
            memcpy_check(ivpad, en.data + en.size - iv.size, iv.size);
        }

        GUARD(cipher_suite->record_alg->cipher->io.cbc.decrypt(session_key, &iv, &en, &en));

        if (conn->actual_protocol_version < S2N_TLS11) {
            memcpy_check(implicit_iv, ivpad, iv.size);
        }
        break;
    case S2N_AEAD:
        /* Skip explicit IV for decryption */
        en.size -= cipher_suite->record_alg->cipher->io.aead.record_iv_size;
        en.data += cipher_suite->record_alg->cipher->io.aead.record_iv_size;

        /* Check that we have some data to decrypt */
        ne_check(en.size, 0);

        GUARD(cipher_suite->record_alg->cipher->io.aead.decrypt(session_key, &iv, &aad, &en, &en));
        break;
    case S2N_COMPOSITE:
        ne_check(en.size, 0);
        eq_check(en.size % iv.size,  0);

        /* Copy the last encrypted block to be the next IV */
        memcpy_check(ivpad, en.data + en.size - iv.size, iv.size);

        /* This will: Skip the explicit IV(if applicable), decrypt the payload, verify the MAC and padding. */
        GUARD((cipher_suite->record_alg->cipher->io.comp.decrypt(session_key, &iv, &en, &en)));

        memcpy_check(implicit_iv, ivpad, iv.size);
        break;
    default:
        S2N_ERROR(S2N_ERR_CIPHER_TYPE);
        break;
    }

    /* Subtract the padding length */
    if (cipher_suite->record_alg->cipher->type == S2N_CBC || cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        gt_check(en.size, 0);
        payload_length -= (en.data[en.size - 1] + 1);
    }

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

    /* Padding */
    if (cipher_suite->record_alg->cipher->type == S2N_CBC) {
        if (s2n_verify_cbc(conn, mac, &en) < 0) {
            GUARD(s2n_stuffer_wipe(&conn->in));
            S2N_ERROR(S2N_ERR_BAD_MESSAGE);
        }
    } else {
        /* MAC check for streaming ciphers - no padding */
        GUARD(s2n_hmac_update(mac, en.data, payload_length));

        uint8_t check_digest[S2N_MAX_DIGEST_LEN];
        lte_check(mac_digest_size, sizeof(check_digest));
        GUARD(s2n_hmac_digest(mac, check_digest, mac_digest_size));

        if (s2n_hmac_digest_verify(en.data + payload_length, check_digest, mac_digest_size) < 0) {
            GUARD(s2n_stuffer_wipe(&conn->in));
            S2N_ERROR(S2N_ERR_BAD_MESSAGE);
        }
    }

    /* O.k., we've successfully read and decrypted the record, now we need to align the stuffer
     * for reading the plaintext data.
     */
    GUARD(s2n_stuffer_reread(&conn->in));
    GUARD(s2n_stuffer_reread(&conn->header_in));

    /* Skip the IV, if any */
    if (cipher_suite->record_alg->cipher->type == S2N_CBC && conn->actual_protocol_version > S2N_TLS10) {
        GUARD(s2n_stuffer_skip_read(&conn->in, cipher_suite->record_alg->cipher->io.cbc.record_iv_size));
    } else if (cipher_suite->record_alg->cipher->type == S2N_AEAD && conn->actual_protocol_version >= S2N_TLS12) {
        GUARD(s2n_stuffer_skip_read(&conn->in, cipher_suite->record_alg->cipher->io.aead.record_iv_size));
    } else if (cipher_suite->record_alg->cipher->type == S2N_COMPOSITE && conn->actual_protocol_version > S2N_TLS10) {
        GUARD(s2n_stuffer_skip_read(&conn->in, cipher_suite->record_alg->cipher->io.comp.record_iv_size));
    }

    /* Truncate and wipe the MAC and any padding */
    GUARD(s2n_stuffer_wipe_n(&conn->in, s2n_stuffer_data_available(&conn->in) - payload_length));
    conn->in_status = PLAINTEXT;

    return 0;
}
