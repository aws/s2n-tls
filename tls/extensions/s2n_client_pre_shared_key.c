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

#include "tls/extensions/s2n_client_pre_shared_key.h"

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_tls13.h"

static int s2n_client_pre_shared_key_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static int s2n_client_pre_shared_key_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);
static bool s2n_extension_should_send_if_psk_connection(struct s2n_connection *conn);

const s2n_extension_type s2n_client_pre_shared_key_extension = {
    .iana_value = TLS_EXTENSION_PRESHARED_KEY,
    .is_response = false,
    .send = s2n_client_pre_shared_key_send,
    .recv = s2n_client_pre_shared_key_recv,
    .should_send = s2n_extension_should_send_if_psk_connection,
    .if_missing = s2n_extension_noop_if_missing,
};

static int s2n_client_pre_shared_key_send(struct s2n_connection *conn, struct s2n_stuffer *out) {
    notnull_check(conn);

    /* Send PSK Identities and obfuscated_ticket_age */
    const struct s2n_client_psk_config psk_config = conn->initial.client_psk_config;
    S2N_ERROR_IF(psk_config.psk_vec_len <= 0 || psk_config.psk_vec_len > S2N_PSK_VECTOR_MAX_SIZE, S2N_ERR_INVALID_PSK_VECTOR_LEN);

    GUARD(s2n_stuffer_write_uint16(out, psk_config.psk_vec_len));

    for (size_t i = 0; i < psk_config.psk_vec_len; i++) {
        const struct s2n_psk_identity psk_identity = psk_config.psk_vec[i];
        notnull_check(psk_identity.identity);
        GUARD(s2n_stuffer_write_str(out, psk_identity.identity));
        GUARD(s2n_stuffer_write_uint32(out, psk_identity.obfuscated_ticket_age));
    }

    /* Calculate the PSK Binder value. The PSK binder value forms a binding between a PSK and the current
     * handshake. Each entry in the binders list is computed as an HMAC over a transcript hash containing a 
     * partial ClientHello up to and including the PreSharedKeyExtension.identities field.  
     * That is, it includes all of the ClientHello but not the binders list itself. */ 
    // TODO


    /* Send PSK Binder value */

    return S2N_SUCCESS;
}

static int s2n_client_pre_shared_key_recv(struct s2n_connection *conn, struct s2n_stuffer *extension) {

    /* Obtain the selected PSK Identity, the selected Identity is a index value to the list of PSK Identities sent in the send */ 
    notnull_check(conn);
    GUARD(s2n_stuffer_read_uint16(extension, &conn->initial.client_psk_config.selected_psk_identity));

    uint16_t psk_id_idx =  conn->initial.client_psk_config.selected_psk_identity;
    /* Validate that the selected Identity is within the range sent by the client */ 
    S2N_ERROR_IF(psk_id_idx < 0 || psk_id_idx > conn->initial.client_psk_config.psk_vec_len, S2N_ERR_INVALID_PSK_VECTOR_LEN);

    return S2N_SUCCESS;
}

static bool s2n_extension_should_send_if_psk_connection(struct s2n_connection *conn) {
    notnull_check(conn);
    if (conn->initial.client_psk_config.psk_vec_len > 0) {
        return 1;
    }
    return 0; 
}