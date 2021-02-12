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

#include <s2n.h>
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crypto_constants.h"
#include "tls/s2n_quic_support.h" /* this currently holds the s2n_secret_type_t enum */
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

/* hex requires 2 chars per byte */
#define HEX_ENCODING_SIZE 2

/* https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format */

S2N_RESULT s2n_key_log_hex_encode(struct s2n_stuffer *output, uint8_t *bytes, size_t len)
{
    ENSURE_MUT(output);
    ENSURE_REF(bytes);

    const uint8_t chars[] = "0123456789abcdef";

    for (size_t i = 0; i < len; i++) {
        uint8_t upper = bytes[i] >> 4;
        uint8_t lower = bytes[i] & 0x0f;

        GUARD_AS_RESULT(s2n_stuffer_write_uint8(output, chars[upper]));
        GUARD_AS_RESULT(s2n_stuffer_write_uint8(output, chars[lower]));
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_key_log_tls13_secret(struct s2n_connection *conn, struct s2n_blob *secret, s2n_secret_type_t secret_type)
{
    ENSURE_REF(conn);
    ENSURE_REF(conn->config);
    ENSURE_REF(secret);

    /* only emit keys if the callback has been set */
    if (!conn->config->key_log_cb) {
        return S2N_RESULT_OK;
    }

    const uint8_t client_early_traffic_label[] = "CLIENT_EARLY_TRAFFIC_SECRET ";
    const uint8_t client_handshake_label[] = "CLIENT_HANDSHAKE_TRAFFIC_SECRET ";
    const uint8_t server_handshake_label[] = "SERVER_HANDSHAKE_TRAFFIC_SECRET ";
    const uint8_t client_traffic_label[] = "CLIENT_TRAFFIC_SECRET_0 ";
    const uint8_t server_traffic_label[] = "SERVER_TRAFFIC_SECRET_0 ";

    const uint8_t *label = NULL;
    uint8_t label_size = 0;

    switch (secret_type) {
        case S2N_CLIENT_EARLY_TRAFFIC_SECRET:
            label = client_early_traffic_label;
            label_size = sizeof(client_early_traffic_label) - 1;
            break;
        case S2N_CLIENT_HANDSHAKE_TRAFFIC_SECRET:
            label = client_handshake_label;
            label_size = sizeof(client_handshake_label) - 1;
            break;
        case S2N_SERVER_HANDSHAKE_TRAFFIC_SECRET:
            label = server_handshake_label;
            label_size = sizeof(server_handshake_label) - 1;
            break;
        case S2N_CLIENT_APPLICATION_TRAFFIC_SECRET:
            label = client_traffic_label;
            label_size = sizeof(client_traffic_label) - 1;
            break;
        case S2N_SERVER_APPLICATION_TRAFFIC_SECRET:
            label = server_traffic_label;
            label_size = sizeof(server_traffic_label) - 1;
            break;
        default:
            BAIL(S2N_ERR_SAFETY);
    }

    const uint8_t len
        = label_size
        + S2N_TLS_RANDOM_DATA_LEN * HEX_ENCODING_SIZE
        + 1 /* SPACE */
        + secret->size * HEX_ENCODING_SIZE;

    DEFER_CLEANUP(struct s2n_stuffer output, s2n_stuffer_free);
    GUARD_AS_RESULT(s2n_stuffer_alloc(&output, len));

    GUARD_AS_RESULT(s2n_stuffer_write_bytes(&output, label, label_size));
    GUARD_RESULT(s2n_key_log_hex_encode(&output, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD_AS_RESULT(s2n_stuffer_write_uint8(&output, ' '));
    GUARD_RESULT(s2n_key_log_hex_encode(&output, secret->data, secret->size));

    uint8_t *data = s2n_stuffer_raw_read(&output, len);
    ENSURE_REF(data);

    conn->config->key_log_cb(conn->config->key_log_ctx, conn, data, len);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_key_log_tls12_secret(struct s2n_connection *conn, struct s2n_stuffer *output)
{
    ENSURE_REF(conn);
    ENSURE_MUT(output);

    /* only emit keys if the callback has been set */
    if (!conn->config->key_log_cb) {
        return S2N_RESULT_OK;
    }

    /* const uint8_t client_random_label[] = "CLIENT_RANDOM "; */

    /* TODO */

    return S2N_RESULT_OK;
}

