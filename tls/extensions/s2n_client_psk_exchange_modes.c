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

#include "tls/extensions/s2n_client_psk_exchange_modes.h"

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_tls13.h"

static int s2n_client_psk_exchange_modes_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static bool s2n_extension_should_send_if_psk_connection(struct s2n_connection *conn);

const s2n_extension_type s2n_client_psk_exchange_modes_extension = {
    .iana_value = TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES,
    .is_response = false,
    .send = s2n_client_psk_exchange_modes_send,
    .recv = false,
    .should_send = s2n_extension_should_send_if_psk_connection,
    .if_missing = s2n_extension_noop_if_missing,
};

static int s2n_client_psk_exchange_modes_send(struct s2n_connection *conn, struct s2n_stuffer *out) {
    notnull_check(conn);

    /* Send PSK Key Exchange Mode psk_dhe_ke(1). In this mode, the
     * client and server MUST supply "key_share" values as described in rfc8446#section-4.2.8 */
    GUARD(s2n_stuffer_write_uint8(out, S2N_PSK_DHE_KE));
    return S2N_SUCCESS;
}

static bool s2n_extension_should_send_if_psk_connection(struct s2n_connection *conn) {
    notnull_check(conn);
    if (conn->initial.client_psk_config.psk_vec_len <= 0 || conn->initial.client_psk_config.psk_vec_len > S2N_PSK_VECTOR_MAX_SIZE) {
        return 0;
    }
    return 1;
}
