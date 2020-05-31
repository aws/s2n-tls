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

#include "tls/extensions/s2n_server_key_share.h"

#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"

#include "utils/s2n_safety.h"

static int s2n_server_key_share_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static int s2n_server_key_share_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

const s2n_extension_type s2n_server_key_share_extension = {
    .iana_value = TLS_EXTENSION_KEY_SHARE,
    .is_response = false,
    .send = s2n_server_key_share_send,
    .recv = s2n_server_key_share_recv,
    .should_send = s2n_extension_send_if_tls13_connection,
    .if_missing = s2n_extension_noop_if_missing,
};

int s2n_extensions_server_key_share_send_check(struct s2n_connection *conn);

static int s2n_server_key_share_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    GUARD(s2n_extensions_server_key_share_send_check(conn));
    notnull_check(conn);
    notnull_check(out);

    /* Retry requests only require the selected named group, not an actual share.
     * https://tools.ietf.org/html/rfc8446#section-4.2.8 */
    if (s2n_is_hello_retry_message(conn)) {
        notnull_check(conn->secure.server_ecc_evp_params.negotiated_curve);

        /* There was a mutually supported group, so that is the group we will select */
        uint16_t curve = conn->secure.server_ecc_evp_params.negotiated_curve->iana_id;
        GUARD(s2n_stuffer_write_uint16(out, curve));
        return 0;
    }
    conn->secure.server_ecc_evp_params.evp_pkey = NULL;
    GUARD(s2n_ecdhe_parameters_send(&conn->secure.server_ecc_evp_params, out));

    return S2N_SUCCESS;
}

/*
 * From https://tools.ietf.org/html/rfc8446#section-4.2.8
 *
 * If using (EC)DHE key establishment, servers offer exactly one
 * KeyShareEntry in the ServerHello.  This value MUST be in the same
 * group as the KeyShareEntry value offered by the client that the
 * server has selected for the negotiated key exchange.
 */
static int s2n_server_key_share_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    if (!s2n_is_tls13_enabled()) {
        return S2N_SUCCESS;
    }

    notnull_check(conn);
    notnull_check(extension);

    uint16_t named_group;
    S2N_ERROR_IF(s2n_stuffer_data_available(extension) < sizeof(named_group), S2N_ERR_BAD_KEY_SHARE);
    GUARD(s2n_stuffer_read_uint16(extension, &named_group));

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    notnull_check(ecc_pref);

    int supported_curve_index = -1;
    for (int i = 0; i < ecc_pref->count; i++) {
        if (named_group == ecc_pref->ecc_curves[i]->iana_id) {
            supported_curve_index = i;
            break;
        }
    }

    S2N_ERROR_IF(supported_curve_index < 0, S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

    /* If this is a HelloRetryRequest, we won't have a key share. We just have the selected group.
     * Set the server negotiated curve and exit early so a proper keyshare can be generated. 
     */
    if (s2n_is_hello_retry_handshake(conn)) {
        struct s2n_ecc_evp_params* server_ecc_evp_params = &conn->secure.server_ecc_evp_params;
        server_ecc_evp_params->negotiated_curve = ecc_pref->ecc_curves[supported_curve_index];
        return 0;
    }

    /* Key share not sent by client */
    S2N_ERROR_IF(conn->secure.client_ecc_evp_params[supported_curve_index].evp_pkey == NULL, S2N_ERR_BAD_KEY_SHARE);

    struct s2n_ecc_evp_params* server_ecc_evp_params = &conn->secure.server_ecc_evp_params;
    server_ecc_evp_params->negotiated_curve = ecc_pref->ecc_curves[supported_curve_index];

    uint16_t share_size;
    S2N_ERROR_IF(s2n_stuffer_data_available(extension) < sizeof(share_size), S2N_ERR_BAD_KEY_SHARE);
    GUARD(s2n_stuffer_read_uint16(extension, &share_size));
    S2N_ERROR_IF(s2n_stuffer_data_available(extension) < share_size, S2N_ERR_BAD_KEY_SHARE);

    /* Proceed to parse share */
    struct s2n_blob point_blob;
    S2N_ERROR_IF(s2n_ecc_evp_read_params_point(extension, share_size,  &point_blob) < 0, S2N_ERR_BAD_KEY_SHARE);
    S2N_ERROR_IF(s2n_ecc_evp_parse_params_point(&point_blob, server_ecc_evp_params) < 0, S2N_ERR_BAD_KEY_SHARE);

    return S2N_SUCCESS;
}

/*
 * Check whether client has sent a corresponding curve and key_share
 */
int s2n_extensions_server_key_share_send_check(struct s2n_connection *conn)
{
    notnull_check(conn);

    /* If we are responding to a retry request then we don't have a valid
     * curve from the client. Just return 0 so a selected group will be
     * chosen for the key share. */
    if (s2n_is_hello_retry_handshake(conn)) {
        return 0;
    }

    const struct s2n_ecc_named_curve *server_curve;
    server_curve = conn->secure.server_ecc_evp_params.negotiated_curve;
    notnull_check(server_curve);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    notnull_check(ecc_pref);

    int curve_index = -1;
    for (int i = 0; i < ecc_pref->count; i++) {
        if (server_curve == ecc_pref->ecc_curves[i]) {
            curve_index = i;
            break;
        }
    }

    S2N_ERROR_IF(curve_index < 0, S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

    const struct s2n_ecc_evp_params client_ecc_evp = conn->secure.client_ecc_evp_params[curve_index];
    const struct s2n_ecc_named_curve *client_curve = client_ecc_evp.negotiated_curve;

    S2N_ERROR_IF(client_curve == NULL, S2N_ERR_BAD_KEY_SHARE);
    S2N_ERROR_IF(client_curve != server_curve, S2N_ERR_BAD_KEY_SHARE);
    S2N_ERROR_IF(client_ecc_evp.evp_pkey == NULL, S2N_ERR_BAD_KEY_SHARE);

    return 0;
}

/*
 * Selects highest priority mutually supported keyshare
 */
int s2n_extensions_server_key_share_select(struct s2n_connection *conn)
{
    notnull_check(conn);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    notnull_check(ecc_pref);

    for (uint32_t i = 0; i < ecc_pref->count; i++) {
        /* Checks supported group and keyshare have both been sent */
        if (conn->secure.client_ecc_evp_params[i].negotiated_curve &&
                conn->secure.mutually_supported_groups[i]) {
            conn->secure.server_ecc_evp_params.negotiated_curve = conn->secure.client_ecc_evp_params[i].negotiated_curve;
            return 0;
        }
    }

    /* Client sent no keyshares, need to send Hello Retry Request with first negotiated curve */
    if (conn->secure.server_ecc_evp_params.negotiated_curve) {
        GUARD(s2n_set_hello_retry_handshake(conn));
        return 0;
    }

    S2N_ERROR(S2N_ERR_ECDHE_UNSUPPORTED_CURVE);
}

/* Old-style extension functions -- remove after extensions refactor is complete */

/*
 * Calculate the data length for Server Key Share extension
 * based on negotiated_curve selected in server_ecc_evp_params.
 *
 * Retry requests have a different key share format,
 * https://tools.ietf.org/html/rfc8446#section-4.2.8
 *
 * This functions does not error, but s2n_extensions_server_key_share_send() would
 */
int s2n_extensions_server_key_share_send_size(struct s2n_connection *conn)
{
    const struct s2n_ecc_named_curve* curve = conn->secure.server_ecc_evp_params.negotiated_curve;
    int key_share_size = S2N_SIZE_OF_EXTENSION_TYPE
        + S2N_SIZE_OF_EXTENSION_DATA_SIZE
        + S2N_SIZE_OF_NAMED_GROUP;

    /* If this is a KeyShareHelloRetryRequest we don't include the share size */
    if (s2n_is_hello_retry_message(conn)) {
        return key_share_size;
    }

    if (curve == NULL) {
        return 0;
    }

    /* If this is a full KeyShareEntry, include the share size */
    key_share_size += (S2N_SIZE_OF_KEY_SHARE_SIZE + curve->share_size);

    return key_share_size;
}

/*
 * Sends Key Share extension in Server Hello.
 *
 * Expects negotiated_curve to be set and generates a ephemeral key for key sharing
 */
int s2n_extensions_server_key_share_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    return s2n_extension_send(&s2n_server_key_share_extension, conn, out);
}

/*
 * Client receives a Server Hello key share.
 *
 * If the curve is supported, conn->secure.server_ecc_evp_params will be set.
 */
int s2n_extensions_server_key_share_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    return s2n_extension_recv(&s2n_server_key_share_extension, conn, extension);
}
