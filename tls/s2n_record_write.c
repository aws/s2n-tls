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

/* How much overhead does the IV, MAC, TAG and padding bytes introduce ? */
static uint16_t overhead(struct s2n_connection *conn)
{
    struct s2n_crypto_parameters *active = conn->server;

    if (conn->mode == S2N_CLIENT) {
        active = conn->client;
    }

    uint8_t extra;
    GUARD(s2n_hmac_digest_size(active->cipher_suite->record_alg->hmac_alg, &extra));

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

    return extra;
}

int s2n_record_max_write_payload_size(struct s2n_connection *conn)
{
    uint16_t max_fragment_size = conn->max_outgoing_fragment_length;
    struct s2n_crypto_parameters *active = conn->server;

    if (conn->mode == S2N_CLIENT) {
        active = conn->client;
    }

    /* Round the fragment size down to be block aligned */
    if (active->cipher_suite->record_alg->cipher->type == S2N_CBC) {
        max_fragment_size -= max_fragment_size % active->cipher_suite->record_alg->cipher->io.cbc.block_size;
    } else if (active->cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        max_fragment_size -= max_fragment_size % active->cipher_suite->record_alg->cipher->io.comp.block_size;
        /* Composite digest length */
        max_fragment_size -= active->cipher_suite->record_alg->cipher->io.comp.mac_key_size;
        /* Padding length byte */
        max_fragment_size -= 1;
    }

    return max_fragment_size - overhead(conn);
}

int s2n_record_write(struct s2n_connection *conn, uint8_t content_type, struct s2n_blob *in)
{
    struct s2n_blob out, iv, aad;
    uint8_t padding = 0;
    uint16_t block_size = 0;
    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    uint8_t aad_gen[S2N_TLS_MAX_AAD_LEN] = { 0 };
    uint8_t aad_iv[S2N_TLS_MAX_IV_LEN] = { 0 };

    uint8_t *sequence_number = conn->server->server_sequence_number;
    struct s2n_hmac_state *mac = &conn->server->server_record_mac;
    struct s2n_session_key *session_key = &conn->server->server_key;
    struct s2n_cipher_suite *cipher_suite = conn->server->cipher_suite;
    uint8_t *implicit_iv = conn->server->server_implicit_iv;

    if (conn->mode == S2N_CLIENT) {
        sequence_number = conn->client->client_sequence_number;
        mac = &conn->client->client_record_mac;
        session_key = &conn->client->client_key;
        cipher_suite = conn->client->cipher_suite;
        implicit_iv = conn->client->client_implicit_iv;
    }

    if (s2n_stuffer_data_available(&conn->out)) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    uint8_t mac_digest_size;
    GUARD(s2n_hmac_digest_size(mac->alg, &mac_digest_size));

    /* Before we do anything, we need to figure out what the length of the
     * fragment is going to be. 
     */
    uint16_t data_bytes_to_take = MIN(in->size, s2n_record_max_write_payload_size(conn));

    uint16_t extra = overhead(conn);

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

    /* Compute non-payload parts of the MAC(seq num, type, proto vers, fragment length) for composite ciphers.
     * Composite "encrypt" will MAC the payload data and filling in padding.
     */
    if (cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        /* Only fragment length is needed for MAC, but the EVP ctrl function needs fragment length + eiv len. */
        uint16_t payload_and_eiv_len = data_bytes_to_take;
        if (conn->actual_protocol_version > S2N_TLS10) {
            payload_and_eiv_len += block_size;
        }

        /* Outputs number of extra bytes required for MAC and padding */
        int pad_and_mac_len;
        GUARD(cipher_suite->record_alg->cipher->io.comp.initial_hmac(session_key, sequence_number, content_type, conn->actual_protocol_version,
                                                         payload_and_eiv_len, &pad_and_mac_len));
        extra += pad_and_mac_len;
    }

    /* Rewrite the length to be the actual fragment length */
    uint16_t actual_fragment_length = data_bytes_to_take + padding + extra;
    GUARD(s2n_stuffer_wipe_n(&conn->out, 2));
    GUARD(s2n_stuffer_write_uint16(&conn->out, actual_fragment_length));

    /* If we're AEAD, write the sequence number as an IV, and generate the AAD */
    if (cipher_suite->record_alg->cipher->type == S2N_AEAD) {
        GUARD(s2n_stuffer_write_bytes(&conn->out, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));

        struct s2n_stuffer iv_stuffer;
        iv.data = aad_iv;
        iv.size = sizeof(aad_iv);

        GUARD(s2n_stuffer_init(&iv_stuffer, &iv));
        GUARD(s2n_stuffer_write_bytes(&iv_stuffer, implicit_iv, cipher_suite->record_alg->cipher->io.aead.fixed_iv_size));
        GUARD(s2n_stuffer_write_bytes(&iv_stuffer, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));

        /* Set the IV size to the amount of data written */
        iv.size = s2n_stuffer_data_available(&iv_stuffer);

        aad.data = aad_gen;
        aad.size = sizeof(aad_gen);

        struct s2n_stuffer ad_stuffer;
        GUARD(s2n_stuffer_init(&ad_stuffer, &aad));
        GUARD(s2n_aead_aad_init(conn, sequence_number, content_type, data_bytes_to_take, &ad_stuffer));
    } else if (cipher_suite->record_alg->cipher->type == S2N_CBC || cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        iv.size = block_size;
        iv.data = implicit_iv;

        /* For TLS1.1/1.2; write the IV with random data */
        if (conn->actual_protocol_version > S2N_TLS10) {
            GUARD(s2n_get_public_random_data(&iv));
            GUARD(s2n_stuffer_write(&conn->out, &iv));
        }
    }

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

    if (cipher_suite->record_alg->cipher->type == S2N_CBC) {
        /* Include padding bytes, each with the value 'p', and
         * include an extra padding length byte, also with the value 'p'.
         */
        for (int i = 0; i <= padding; i++) {
            GUARD(s2n_stuffer_write_uint8(&conn->out, padding));
        }
    }

    /* Rewind to rewrite/encrypt the packet */
    GUARD(s2n_stuffer_rewrite(&conn->out));

    /* Skip the header */
    GUARD(s2n_stuffer_skip_write(&conn->out, S2N_TLS_RECORD_HEADER_LENGTH));

    uint16_t encrypted_length = data_bytes_to_take + mac_digest_size;
    switch (cipher_suite->record_alg->cipher->type) {
	case S2N_AEAD:
		GUARD(s2n_stuffer_skip_write(&conn->out, cipher_suite->record_alg->cipher->io.aead.record_iv_size));
		encrypted_length += cipher_suite->record_alg->cipher->io.aead.tag_size;
		break;
	case S2N_CBC:
		if (conn->actual_protocol_version > S2N_TLS10) {
			/* Leave the IV alone and unencrypted */
			GUARD(s2n_stuffer_skip_write(&conn->out, iv.size));
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

    /* Do the encryption */
    struct s2n_blob en;
    en.size = encrypted_length;
    en.data = s2n_stuffer_raw_write(&conn->out, en.size);
    notnull_check(en.data);

    switch (cipher_suite->record_alg->cipher->type) {
    case S2N_STREAM:
        GUARD(cipher_suite->record_alg->cipher->io.stream.encrypt(session_key, &en, &en));
        break;
    case S2N_CBC:
        GUARD(cipher_suite->record_alg->cipher->io.cbc.encrypt(session_key, &iv, &en, &en));

        /* Copy the last encrypted block to be the next IV */
        if (conn->actual_protocol_version < S2N_TLS11) {
            gte_check(en.size, block_size);
            memcpy_check(implicit_iv, en.data + en.size - block_size, block_size);
        }
        break;
    case S2N_AEAD:
        GUARD(cipher_suite->record_alg->cipher->io.aead.encrypt(session_key, &iv, &aad, &en, &en));
        break;
    case S2N_COMPOSITE:
        /* This will: compute mac, append padding, append padding length, and encrypt */
        GUARD(cipher_suite->record_alg->cipher->io.comp.encrypt(session_key, &iv, &en, &en));

        /* Copy the last encrypted block to be the next IV */
        gte_check(en.size, block_size);
        memcpy_check(implicit_iv, en.data + en.size - block_size, block_size);
        break;
    default:
        S2N_ERROR(S2N_ERR_CIPHER_TYPE);
        break;
    }

    conn->wire_bytes_out += actual_fragment_length + S2N_TLS_RECORD_HEADER_LENGTH;
    return data_bytes_to_take;
}
