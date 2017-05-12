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
uint16_t s2n_record_overhead(struct s2n_connection *conn)
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

    return max_fragment_size - s2n_record_overhead(conn);
}

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

    uint8_t tls_major_version = protocol_version[0];
    /* TLS servers compliant with this specification MUST accept any value {03,XX} as the record layer version number
     * for ClientHello.
     *
     * https://tools.ietf.org/html/rfc5246#appendix-E.1 */
    if (tls_major_version < S2N_MINIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION
        || S2N_MAXIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION < tls_major_version) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

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


