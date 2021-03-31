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

#include <stdint.h>
#include <sys/param.h>

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

extern uint8_t s2n_unknown_protocol_version;

/* How much overhead does the IV, MAC, TAG and padding bytes introduce ? */
static S2N_RESULT s2n_tls_record_overhead(struct s2n_connection *conn, uint16_t *out)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_MUT(out);
    struct s2n_crypto_parameters *active = conn->server;

    if (conn->mode == S2N_CLIENT) {
        active = conn->client;
    }

    uint8_t extra;
    RESULT_GUARD_POSIX(s2n_hmac_digest_size(active->cipher_suite->record_alg->hmac_alg, &extra));

    if (active->cipher_suite->record_alg->cipher->type == S2N_CBC) {
        /* Subtract one for the padding length byte */
        extra += 1;

        if (conn->actual_protocol_version > S2N_TLS10) {
            extra += active->cipher_suite->record_alg->cipher->io.cbc.record_iv_size;
        }
    } else if (active->cipher_suite->record_alg->cipher->type == S2N_AEAD) {
        extra += active->cipher_suite->record_alg->cipher->io.aead.tag_size;
        extra += active->cipher_suite->record_alg->cipher->io.aead.record_iv_size;
    } else if (active->cipher_suite->record_alg->cipher->type == S2N_COMPOSITE && conn->actual_protocol_version > S2N_TLS10) {
        extra += active->cipher_suite->record_alg->cipher->io.comp.record_iv_size;
    }

    *out = extra;

    return S2N_RESULT_OK;
}

/* This function returns maximum size of plaintext data to write for the payload.
 * Record overheads are not included here.
 */
S2N_RESULT s2n_record_max_write_payload_size(struct s2n_connection *conn, uint16_t *max_fragment_size)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_MUT(max_fragment_size);
    RESULT_ENSURE(conn->max_outgoing_fragment_length > 0, S2N_ERR_FRAGMENT_LENGTH_TOO_SMALL);

    *max_fragment_size = MIN(conn->max_outgoing_fragment_length, S2N_TLS_MAXIMUM_FRAGMENT_LENGTH);

    return S2N_RESULT_OK;
}

/* Find the largest size that will fit within an ethernet frame for a "small" payload */
S2N_RESULT s2n_record_min_write_payload_size(struct s2n_connection *conn, uint16_t *payload_size)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_MUT(payload_size);
    /* remove ethernet, TCP/IP and TLS header overheads */
    const uint16_t min_outgoing_fragment_length = ETH_MTU - (conn->ipv6 ? IP_V6_HEADER_LENGTH : IP_V4_HEADER_LENGTH)
        - TCP_HEADER_LENGTH - TCP_OPTIONS_LENGTH - S2N_TLS_RECORD_HEADER_LENGTH;

    RESULT_ENSURE(min_outgoing_fragment_length <= S2N_TLS_MAXIMUM_FRAGMENT_LENGTH, S2N_ERR_FRAGMENT_LENGTH_TOO_LARGE);
    uint16_t size = min_outgoing_fragment_length;

    const struct s2n_crypto_parameters *active = conn->mode == S2N_CLIENT ? conn->client : conn->server;

    /* Round the fragment size down to be block aligned */
    if (active->cipher_suite->record_alg->cipher->type == S2N_CBC) {
        size -= size % active->cipher_suite->record_alg->cipher->io.cbc.block_size;
    } else if (active->cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        size -= size % active->cipher_suite->record_alg->cipher->io.comp.block_size;
        /* Composite digest length */
        size -= active->cipher_suite->record_alg->cipher->io.comp.mac_key_size;
        /* Padding length byte */
        size -= 1;
    }

    /* subtract overheads of a TLS record */
    uint16_t overhead = 0;
    RESULT_GUARD(s2n_tls_record_overhead(conn, &overhead));
    RESULT_ENSURE(size > overhead, S2N_ERR_FRAGMENT_LENGTH_TOO_SMALL);
    size -= overhead;

    RESULT_ENSURE(size > 0, S2N_ERR_FRAGMENT_LENGTH_TOO_SMALL);
    RESULT_ENSURE(size <= ETH_MTU, S2N_ERR_FRAGMENT_LENGTH_TOO_LARGE);

    *payload_size = size;

    return S2N_RESULT_OK;
}

int s2n_record_write_protocol_version(struct s2n_connection *conn)
{
    uint8_t record_protocol_version = conn->actual_protocol_version;
    if (conn->server_protocol_version == s2n_unknown_protocol_version
            && conn->early_data_state != S2N_EARLY_DATA_REQUESTED) {
        /* Some legacy TLS implementations can't handle records with protocol version higher than TLS1.0.
         * To provide maximum compatibility, send record version as TLS1.0 if server protocol version isn't
         * established yet, which happens only during ClientHello message. Note, this has no effect on
         * protocol version in ClientHello, so we're still able to negotiate protocol versions above TLS1.0 */
        record_protocol_version = MIN(record_protocol_version, S2N_TLS10);
    }

    /* In accordance to TLS 1.3 spec, https://tools.ietf.org/html/rfc8446#section-5.1
     * tls record version should never be greater than 33 (legacy TLS 1.2 version).
     */
    record_protocol_version = MIN(record_protocol_version, S2N_TLS12);

    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    protocol_version[0] = record_protocol_version / 10;
    protocol_version[1] = record_protocol_version % 10;

    POSIX_GUARD(s2n_stuffer_write_bytes(&conn->out, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

    return 0;
}

static inline int s2n_record_encrypt(
    struct s2n_connection *conn,
    const struct s2n_cipher_suite *cipher_suite,
    struct s2n_session_key *session_key,
    struct s2n_blob *iv,
    struct s2n_blob *aad,
    struct s2n_blob *en,
    uint8_t *implicit_iv, uint16_t block_size)
{
    POSIX_ENSURE_REF(en->data);

    switch (cipher_suite->record_alg->cipher->type) {
    case S2N_STREAM:
        POSIX_GUARD(cipher_suite->record_alg->cipher->io.stream.encrypt(session_key, en, en));
        break;
    case S2N_CBC:
        POSIX_GUARD(cipher_suite->record_alg->cipher->io.cbc.encrypt(session_key, iv, en, en));

        /* Copy the last encrypted block to be the next IV */
        if (conn->actual_protocol_version < S2N_TLS11) {
            POSIX_ENSURE_GTE(en->size, block_size);
            POSIX_CHECKED_MEMCPY(implicit_iv, en->data + en->size - block_size, block_size);
        }
        break;
    case S2N_AEAD:
        POSIX_GUARD(cipher_suite->record_alg->cipher->io.aead.encrypt(session_key, iv, aad, en, en));
        break;
    case S2N_COMPOSITE:
        /* This will: compute mac, append padding, append padding length, and encrypt */
        POSIX_GUARD(cipher_suite->record_alg->cipher->io.comp.encrypt(session_key, iv, en, en));

        /* Copy the last encrypted block to be the next IV */
        POSIX_ENSURE_GTE(en->size, block_size);
        POSIX_CHECKED_MEMCPY(implicit_iv, en->data + en->size - block_size, block_size);
        break;
    default:
        POSIX_BAIL(S2N_ERR_CIPHER_TYPE);
        break;
    }

    return 0;
}

int s2n_record_writev(struct s2n_connection *conn, uint8_t content_type, const struct iovec *in, int in_count, size_t offs, size_t to_write)
{
    struct s2n_blob iv = { 0 };
    uint8_t padding = 0;
    uint16_t block_size = 0;
    uint8_t aad_iv[S2N_TLS_MAX_IV_LEN] = { 0 };

    /* In TLS 1.3, handle CCS message as unprotected records */
    struct s2n_crypto_parameters *current_client_crypto = conn->client;
    struct s2n_crypto_parameters *current_server_crypto = conn->server;
    if (conn->actual_protocol_version == S2N_TLS13 && content_type == TLS_CHANGE_CIPHER_SPEC) {
        conn->client = &conn->initial;
        conn->server = &conn->initial;
    }

    uint8_t *sequence_number = conn->server->server_sequence_number;
    struct s2n_hmac_state *mac = &conn->server->server_record_mac;
    struct s2n_session_key *session_key = &conn->server->server_key;
    const struct s2n_cipher_suite *cipher_suite = conn->server->cipher_suite;
    uint8_t *implicit_iv = conn->server->server_implicit_iv;

    if (conn->mode == S2N_CLIENT) {
        sequence_number = conn->client->client_sequence_number;
        mac = &conn->client->client_record_mac;
        session_key = &conn->client->client_key;
        cipher_suite = conn->client->cipher_suite;
        implicit_iv = conn->client->client_implicit_iv;
    }

    const int is_tls13_record = cipher_suite->record_alg->flags & S2N_TLS13_RECORD_AEAD_NONCE;
    s2n_stack_blob(aad, is_tls13_record ? S2N_TLS13_AAD_LEN : S2N_TLS_MAX_AAD_LEN, S2N_TLS_MAX_AAD_LEN);

    S2N_ERROR_IF(s2n_stuffer_data_available(&conn->out), S2N_ERR_RECORD_STUFFER_NEEDS_DRAINING);

    uint8_t mac_digest_size;
    POSIX_GUARD(s2n_hmac_digest_size(mac->alg, &mac_digest_size));

    /* Before we do anything, we need to figure out what the length of the
     * fragment is going to be.
     */
    uint16_t max_write_payload_size = 0;
    POSIX_GUARD_RESULT(s2n_record_max_write_payload_size(conn, &max_write_payload_size));
    const uint16_t data_bytes_to_take = MIN(to_write, max_write_payload_size);

    uint16_t extra = 0;
    POSIX_GUARD_RESULT(s2n_tls_record_overhead(conn, &extra));

    /* If we have padding to worry about, figure that out too */
    if (cipher_suite->record_alg->cipher->type == S2N_CBC) {
        block_size = cipher_suite->record_alg->cipher->io.cbc.block_size;
        if (((data_bytes_to_take + extra) % block_size)) {
            padding = block_size - ((data_bytes_to_take + extra) % block_size);
        }
    } else if (cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        block_size = cipher_suite->record_alg->cipher->io.comp.block_size;
    }

    /* Start the MAC with the sequence number */
    POSIX_GUARD(s2n_hmac_update(mac, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));

    POSIX_GUARD(s2n_stuffer_resize_if_empty(&conn->out, S2N_LARGE_RECORD_LENGTH));

    /* Now that we know the length, start writing the record */
    POSIX_GUARD(s2n_stuffer_write_uint8(&conn->out, is_tls13_record ?
        /* tls 1.3 opaque type */ TLS_APPLICATION_DATA :
        /* actual content_type */ content_type ));
    POSIX_GUARD(s2n_record_write_protocol_version(conn));

    /* First write a header that has the payload length, this is for the MAC */
    POSIX_GUARD(s2n_stuffer_write_uint16(&conn->out, data_bytes_to_take));

    if (conn->actual_protocol_version > S2N_SSLv3) {
        POSIX_GUARD(s2n_hmac_update(mac, conn->out.blob.data, S2N_TLS_RECORD_HEADER_LENGTH));
    } else {
        /* SSLv3 doesn't include the protocol version in the MAC */
        POSIX_GUARD(s2n_hmac_update(mac, conn->out.blob.data, 1));
        POSIX_GUARD(s2n_hmac_update(mac, conn->out.blob.data + 3, 2));
    }

    /* Compute non-payload parts of the MAC(seq num, type, proto vers, fragment length) for composite ciphers.
     * Composite "encrypt" will MAC the payload data and fill in padding.
     */
    if (cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        /* Only fragment length is needed for MAC, but the EVP ctrl function needs fragment length + eiv len. */
        uint16_t payload_and_eiv_len = data_bytes_to_take;
        if (conn->actual_protocol_version > S2N_TLS10) {
            payload_and_eiv_len += block_size;
        }

        /* Outputs number of extra bytes required for MAC and padding */
        int pad_and_mac_len;
        POSIX_GUARD(cipher_suite->record_alg->cipher->io.comp.initial_hmac(session_key, sequence_number, content_type, conn->actual_protocol_version,
                                                                     payload_and_eiv_len, &pad_and_mac_len));
        extra += pad_and_mac_len;
    }

    /* TLS 1.3 protected record occupies one extra byte for content type */
    if (is_tls13_record) {
        extra += TLS13_CONTENT_TYPE_LENGTH;
    }

    /* Rewrite the length to be the actual fragment length */
    const uint16_t actual_fragment_length = data_bytes_to_take + padding + extra;
    /* ensure actual_fragment_length + S2N_TLS_RECORD_HEADER_LENGTH <= max record length */
    const uint16_t max_record_length = is_tls13_record ? S2N_TLS13_MAXIMUM_RECORD_LENGTH : S2N_TLS_MAXIMUM_RECORD_LENGTH;
    S2N_ERROR_IF(actual_fragment_length + S2N_TLS_RECORD_HEADER_LENGTH > max_record_length, S2N_ERR_RECORD_LENGTH_TOO_LARGE);
    POSIX_GUARD(s2n_stuffer_wipe_n(&conn->out, 2));
    POSIX_GUARD(s2n_stuffer_write_uint16(&conn->out, actual_fragment_length));

    /* If we're AEAD, write the sequence number as an IV, and generate the AAD */
    if (cipher_suite->record_alg->cipher->type == S2N_AEAD) {
        struct s2n_stuffer iv_stuffer = {0};
        s2n_blob_init(&iv, aad_iv, sizeof(aad_iv));
        POSIX_GUARD(s2n_stuffer_init(&iv_stuffer, &iv));

        if (cipher_suite->record_alg->flags & S2N_TLS12_AES_GCM_AEAD_NONCE) {
            /* Partially explicit nonce. See RFC 5288 Section 3 */
            POSIX_GUARD(s2n_stuffer_write_bytes(&conn->out, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
            POSIX_GUARD(s2n_stuffer_write_bytes(&iv_stuffer, implicit_iv, cipher_suite->record_alg->cipher->io.aead.fixed_iv_size));
            POSIX_GUARD(s2n_stuffer_write_bytes(&iv_stuffer, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
        } else if (cipher_suite->record_alg->flags & S2N_TLS12_CHACHA_POLY_AEAD_NONCE || is_tls13_record) {
            /* Fully implicit nonce. See RFC7905 Section 2 */
            uint8_t four_zeroes[4] = { 0 };
            POSIX_GUARD(s2n_stuffer_write_bytes(&iv_stuffer, four_zeroes, 4));
            POSIX_GUARD(s2n_stuffer_write_bytes(&iv_stuffer, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
            for(int i = 0; i < cipher_suite->record_alg->cipher->io.aead.fixed_iv_size; i++) {
                aad_iv[i] = aad_iv[i] ^ implicit_iv[i];
            }
        } else {
            POSIX_BAIL(S2N_ERR_INVALID_NONCE_TYPE);
        }

        /* Set the IV size to the amount of data written */
        iv.size = s2n_stuffer_data_available(&iv_stuffer);

        struct s2n_stuffer ad_stuffer = {0};
        POSIX_GUARD(s2n_stuffer_init(&ad_stuffer, &aad));
        if (is_tls13_record) {
            POSIX_GUARD_RESULT(s2n_tls13_aead_aad_init(data_bytes_to_take + TLS13_CONTENT_TYPE_LENGTH, cipher_suite->record_alg->cipher->io.aead.tag_size, &ad_stuffer));
        } else {
            POSIX_GUARD_RESULT(s2n_aead_aad_init(conn, sequence_number, content_type, data_bytes_to_take, &ad_stuffer));
        }
    } else if (cipher_suite->record_alg->cipher->type == S2N_CBC || cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        s2n_blob_init(&iv, implicit_iv, block_size);

        /* For TLS1.1/1.2; write the IV with random data */
        if (conn->actual_protocol_version > S2N_TLS10) {
            POSIX_GUARD_RESULT(s2n_get_public_random_data(&iv));
            if (cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
                /* Write a separate random block to the record. This will be used along with the previously generated
                 * iv blob to generate the final explicit_iv for this record.
                 *
                 * How? Openssl's AES-CBC stitched encrypt populates the first block of application data with:
                 * AES(Key, XOR(iv, initial_block))
                 *
                 * If we make initial_block a random block unrelated to random_iv, explicit IV for this record
                 * is random value based on the two random blobs we just generated:
                 * AES(Key, XOR(random_iv, explicit_iv_placeholder) == AES(Key, XOR(random_iv, random_iv2))
                 *
                 * NOTE: We can't use the same random IV blob as both the initial block and IV since it will result in:
                 * AES(Key, XOR(random_iv, random_iv)) == AES(Key, 0), which will be shared by all records in this session.
                 */
                struct s2n_blob explicit_iv_placeholder;
                uint8_t zero_block[S2N_TLS_MAX_IV_LEN] = { 0 };
                POSIX_GUARD(s2n_blob_init(&explicit_iv_placeholder, zero_block, block_size));
                POSIX_GUARD_RESULT(s2n_get_public_random_data(&explicit_iv_placeholder));
                POSIX_GUARD(s2n_stuffer_write(&conn->out, &explicit_iv_placeholder));
            } else {
                /* We can write the explicit IV directly to the record for non composite CBC because
                 * s2n starts AES *after* the explicit IV.
                 */
                POSIX_GUARD(s2n_stuffer_write(&conn->out, &iv));
            }
        }
    }

    /* We are done with this sequence number, so we can increment it */
    struct s2n_blob seq = {.data = sequence_number,.size = S2N_TLS_SEQUENCE_NUM_LEN };
    POSIX_GUARD(s2n_increment_sequence_number(&seq));

    /* Write the plaintext data */
    POSIX_GUARD(s2n_stuffer_writev_bytes(&conn->out, in, in_count, offs, data_bytes_to_take));
    void *orig_write_ptr = conn->out.blob.data + conn->out.write_cursor - data_bytes_to_take;
    POSIX_GUARD(s2n_hmac_update(mac, orig_write_ptr, data_bytes_to_take));

    /* Write the digest */
    uint8_t *digest = s2n_stuffer_raw_write(&conn->out, mac_digest_size);
    POSIX_ENSURE_REF(digest);

    POSIX_GUARD(s2n_hmac_digest(mac, digest, mac_digest_size));
    POSIX_GUARD(s2n_hmac_reset(mac));

    /* Write content type for TLS 1.3 record (RFC 8446 Section 5.2) */
    if (is_tls13_record) {
        POSIX_GUARD(s2n_stuffer_write_uint8(&conn->out, content_type));
    }

    if (cipher_suite->record_alg->cipher->type == S2N_CBC) {
        /* Include padding bytes, each with the value 'p', and
         * include an extra padding length byte, also with the value 'p'.
         */
        for (int i = 0; i <= padding; i++) {
            POSIX_GUARD(s2n_stuffer_write_uint8(&conn->out, padding));
        }
    }

    /* Rewind to rewrite/encrypt the packet */
    POSIX_GUARD(s2n_stuffer_rewrite(&conn->out));

    /* Skip the header */
    POSIX_GUARD(s2n_stuffer_skip_write(&conn->out, S2N_TLS_RECORD_HEADER_LENGTH));

    uint16_t encrypted_length = data_bytes_to_take + mac_digest_size;
    switch (cipher_suite->record_alg->cipher->type) {
    case S2N_AEAD:
        POSIX_GUARD(s2n_stuffer_skip_write(&conn->out, cipher_suite->record_alg->cipher->io.aead.record_iv_size));
        encrypted_length += cipher_suite->record_alg->cipher->io.aead.tag_size;
        if (is_tls13_record) {
            /* one extra byte for content type */
            encrypted_length += TLS13_CONTENT_TYPE_LENGTH;
        }
        break;
    case S2N_CBC:
        if (conn->actual_protocol_version > S2N_TLS10) {
            /* Leave the IV alone and unencrypted */
            POSIX_GUARD(s2n_stuffer_skip_write(&conn->out, iv.size));
        }
        /* Encrypt the padding and the padding length byte too */
        encrypted_length += padding + 1;
        break;
    case S2N_COMPOSITE:
        /* Composite CBC expects a pointer starting at explicit IV: [Explicit IV | fragment | MAC | padding | padding len ]
        * extra will account for the explicit IV len(if applicable), MAC digest len, padding len + padding byte.
        */
        encrypted_length += extra;
        break;
    default:
        break;
    }

    /* Check that stuffer have enough space to write encrypted record, because raw_write cannot expand tainted stuffer */
    S2N_ERROR_IF(s2n_stuffer_space_remaining(&conn->out) < encrypted_length, S2N_ERR_RECORD_STUFFER_SIZE);

    /* Do the encryption */
    struct s2n_blob en = { .size = encrypted_length, .data = s2n_stuffer_raw_write(&conn->out, encrypted_length) };
    POSIX_GUARD(s2n_record_encrypt(conn, cipher_suite, session_key, &iv, &aad, &en, implicit_iv, block_size));

    if (conn->actual_protocol_version == S2N_TLS13 && content_type == TLS_CHANGE_CIPHER_SPEC) {
        conn->client = current_client_crypto;
        conn->server = current_server_crypto;
    }

    conn->wire_bytes_out += actual_fragment_length + S2N_TLS_RECORD_HEADER_LENGTH;

    return data_bytes_to_take;
}

int s2n_record_write(struct s2n_connection *conn, uint8_t content_type, struct s2n_blob *in)
{
    struct iovec iov;
    iov.iov_base = in->data;
    iov.iov_len = in->size;
    return s2n_record_writev(conn, content_type, &iov, 1, 0, in->size);
}
