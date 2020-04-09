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

#include "tls/s2n_client_extensions.h"
#include "tls/s2n_ecc_preferences.h"

#include "utils/s2n_safety.h"
#include "tls/s2n_tls.h"

/*
 * Check whether client has sent a corresponding curve and key_share
 */
int s2n_extensions_server_key_share_send_check(struct s2n_connection *conn)
{
    notnull_check(conn);
    const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
    notnull_check(ecc_pref);

    const struct s2n_ecc_named_curve *server_curve, *client_curve;
    server_curve = conn->secure.server_ecc_evp_params.negotiated_curve;
    notnull_check(server_curve);

    int curve_index = -1;
    for (int i = 0; i < ecc_pref->count; i++) {
        if (server_curve == ecc_pref->ecc_curves[i]) {
            curve_index = i;
            break;
        }
    }
    gt_check(curve_index, -1);

    const struct s2n_ecc_evp_params client_ecc_evp = conn->secure.client_ecc_evp_params[curve_index];
    client_curve = client_ecc_evp.negotiated_curve;

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
    notnull_check(conn->config);
    const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
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
        /* Once hello retry request is implemented in issue #1607, lines can
         be uncommented and error can be removed. 
        GUARD(s2n_server_should_retry(conn));
        return 0; */
        S2N_ERROR(S2N_ERR_BAD_KEY_SHARE);
    }   
    S2N_ERROR(S2N_ERR_ECDHE_UNSUPPORTED_CURVE);
}

/*
 * Calculate the data length for Server Key Share extension
 * based on negotiated_curve selected in server_ecc_evp_params.
 *
 * This functions does not error, but s2n_extensions_server_key_share_send() would
 */
int s2n_extensions_server_key_share_send_size(struct s2n_connection *conn)
{
    const struct s2n_ecc_named_curve* curve = conn->secure.server_ecc_evp_params.negotiated_curve;

    if (curve == NULL) {
        return 0;
    }

    const int key_share_size = S2N_SIZE_OF_EXTENSION_TYPE
        + S2N_SIZE_OF_EXTENSION_DATA_SIZE
        + S2N_SIZE_OF_NAMED_GROUP
        + S2N_SIZE_OF_KEY_SHARE_SIZE
        + curve->share_size;

    return key_share_size;
}

/*
 * Sends Key Share extension in Server Hello.
 *
 * Expects negotiated_curve to be set and generates a ephemeral key for key sharing
 */
int s2n_extensions_server_key_share_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    GUARD(s2n_extensions_server_key_share_send_check(conn));
    notnull_check(out);

    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_KEY_SHARE));
    GUARD(s2n_stuffer_write_uint16(out, s2n_extensions_server_key_share_send_size(conn)
        - S2N_SIZE_OF_EXTENSION_TYPE
        - S2N_SIZE_OF_EXTENSION_DATA_SIZE
    ));

    GUARD(s2n_ecdhe_parameters_send(&conn->secure.server_ecc_evp_params, out));

    return 0;
}

/*
 * Client receives a Server Hello key share.
 *
 * If the curve is supported, conn->secure.server_ecc_evp_params will be set.
 */
int s2n_extensions_server_key_share_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    notnull_check(conn);
    notnull_check(extension);
    notnull_check(conn->config);
    const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
    notnull_check(ecc_pref);

    uint16_t named_group, share_size;

    /* Make sure we can read the next 4 bytes */
    S2N_ERROR_IF(s2n_stuffer_data_available(extension) < 4, S2N_ERR_BAD_KEY_SHARE);

    GUARD(s2n_stuffer_read_uint16(extension, &named_group));
    GUARD(s2n_stuffer_read_uint16(extension, &share_size));

    /* and the remaining amount of bytes */
    S2N_ERROR_IF(s2n_stuffer_data_available(extension) < share_size, S2N_ERR_BAD_KEY_SHARE);

    int supported_curve_index = -1;
    const struct s2n_ecc_named_curve *supported_curve = NULL;
    for (int i = 0; i < ecc_pref->count; i++) {
        if (named_group == ecc_pref->ecc_curves[i]->iana_id) {
            supported_curve_index = i;
            supported_curve = ecc_pref->ecc_curves[i];
            break;
        }
    }

    /*
     * From https://tools.ietf.org/html/rfc8446#section-4.2.8
     *
     * If using (EC)DHE key establishment, servers offer exactly one
     * KeyShareEntry in the ServerHello.  This value MUST be in the same
     * group as the KeyShareEntry value offered by the client that the
     * server has selected for the negotiated key exchange.
     */

    /* Key share unsupported by s2n */
    S2N_ERROR_IF(supported_curve == NULL, S2N_ERR_BAD_KEY_SHARE);
    S2N_ERROR_IF(supported_curve_index == -1, S2N_ERR_BAD_KEY_SHARE);

    /* Key share not sent by client */
    S2N_ERROR_IF(conn->secure.client_ecc_evp_params[supported_curve_index].evp_pkey == NULL, S2N_ERR_BAD_KEY_SHARE);

    struct s2n_ecc_evp_params* server_ecc_evp_params = &conn->secure.server_ecc_evp_params;
    server_ecc_evp_params->negotiated_curve = supported_curve;

    /* Proceed to parse curve */
    struct s2n_blob point_blob;

    S2N_ERROR_IF(s2n_ecc_evp_read_params_point(extension, share_size,  &point_blob) < 0, S2N_ERR_BAD_KEY_SHARE);
    S2N_ERROR_IF(s2n_ecc_evp_parse_params_point(&point_blob, server_ecc_evp_params) < 0, S2N_ERR_BAD_KEY_SHARE);

    return 0;
}
