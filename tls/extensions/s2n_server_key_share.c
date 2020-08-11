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

#include "crypto/s2n_fips.h"

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

    GUARD(s2n_ecdhe_parameters_send(&conn->secure.server_ecc_evp_params, out));

    return S2N_SUCCESS;
}

static int s2n_server_key_share_recv_pq_hybrid(struct s2n_connection *conn, uint16_t named_group_iana,
        struct s2n_stuffer *extension) {
    notnull_check(conn);
    notnull_check(extension);

    ENSURE_POSIX(s2n_is_in_fips_mode() == false, S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS);

    const struct s2n_kem_preferences *kem_pref = NULL;
    GUARD(s2n_connection_get_kem_preferences(conn, &kem_pref));
    notnull_check(kem_pref);

    /* This check should have been done higher up, but including it here as well for extra defense.
     * Uses S2N_ERR_ECDHE_UNSUPPORTED_CURVE for backward compatibility. */
    ENSURE_POSIX(s2n_kem_preferences_includes_tls13_kem_group(kem_pref, named_group_iana), S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

    size_t kem_group_index = 0;
    for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
        if (named_group_iana == kem_pref->tls13_kem_groups[i]->iana_id) {
            kem_group_index = i;
            break;
        }
    }

    struct s2n_kem_group_params *server_kem_group_params = &conn->secure.server_kem_group_params;
    server_kem_group_params->kem_group = kem_pref->tls13_kem_groups[kem_group_index];
    server_kem_group_params->kem_params.kem = kem_pref->tls13_kem_groups[kem_group_index]->kem;
    server_kem_group_params->ecc_params.negotiated_curve = kem_pref->tls13_kem_groups[kem_group_index]->curve;

    if (s2n_is_hello_retry_message(conn)) {
        S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
    }

    /* Ensure that the server's key share corresponds with a key share previously sent by the client */
    ENSURE_POSIX(conn->secure.client_kem_group_params[kem_group_index].kem_params.private_key.data != NULL,
                 S2N_ERR_BAD_KEY_SHARE);
    ENSURE_POSIX(conn->secure.client_kem_group_params[kem_group_index].ecc_params.evp_pkey != NULL,
            S2N_ERR_BAD_KEY_SHARE);
    notnull_check(conn->secure.client_kem_group_params[kem_group_index].kem_group);
    eq_check(conn->secure.client_kem_group_params[kem_group_index].kem_group->iana_id, named_group_iana);
    conn->secure.chosen_client_kem_group_params = &conn->secure.client_kem_group_params[kem_group_index];

    /* The structure of the PQ share should be:
     *    total share size (2 bytes)
     * || size of ECC key share (2 bytes)
     * || ECC key share (variable bytes)
     * || size of PQ key share (2 bytes)
     * || PQ key share (variable bytes) */
    uint16_t received_total_share_size;
    GUARD(s2n_stuffer_read_uint16(extension, &received_total_share_size));

    uint16_t expected_total_share_size =
            S2N_SIZE_OF_KEY_SHARE_SIZE
            + server_kem_group_params->kem_group->curve->share_size
            + S2N_SIZE_OF_KEY_SHARE_SIZE
            + server_kem_group_params->kem_group->kem->ciphertext_length;
    ENSURE_POSIX(received_total_share_size == expected_total_share_size, S2N_ERR_BAD_KEY_SHARE);
    ENSURE_POSIX(s2n_stuffer_data_available(extension) == received_total_share_size, S2N_ERR_BAD_KEY_SHARE);

    /* Parse ECC key share */
    uint16_t ecc_share_size;
    struct s2n_blob point_blob;
    GUARD(s2n_stuffer_read_uint16(extension, &ecc_share_size));
    ENSURE_POSIX(s2n_ecc_evp_read_params_point(extension, ecc_share_size, &point_blob) == S2N_SUCCESS, S2N_ERR_BAD_KEY_SHARE);
    ENSURE_POSIX(s2n_ecc_evp_parse_params_point(&point_blob, &server_kem_group_params->ecc_params) == S2N_SUCCESS, S2N_ERR_BAD_KEY_SHARE);
    ENSURE_POSIX(server_kem_group_params->ecc_params.evp_pkey != NULL, S2N_ERR_BAD_KEY_SHARE);

    /* Parse the PQ KEM key share */
    ENSURE_POSIX(s2n_kem_recv_ciphertext(extension, &conn->secure.chosen_client_kem_group_params->kem_params) == S2N_SUCCESS,
            S2N_ERR_BAD_KEY_SHARE);

    return S2N_SUCCESS;
}

static int s2n_server_key_share_recv_ecc(struct s2n_connection *conn, uint16_t named_group_iana,
        struct s2n_stuffer *extension) {
    notnull_check(conn);
    notnull_check(extension);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    notnull_check(ecc_pref);

    /* This check should have been done higher up, but including it here as well for extra defense. */
    ENSURE_POSIX(s2n_ecc_preferences_includes_curve(ecc_pref, named_group_iana),
            S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

    size_t supported_curve_index = 0;

    for (size_t i = 0; i < ecc_pref->count; i++) {
        if (named_group_iana == ecc_pref->ecc_curves[i]->iana_id) {
            supported_curve_index = i;
            break;
        }
    }

    struct s2n_ecc_evp_params *server_ecc_evp_params = &conn->secure.server_ecc_evp_params;
    server_ecc_evp_params->negotiated_curve = ecc_pref->ecc_curves[supported_curve_index];

    /* If this is a HelloRetryRequest, we won't have a key share. We just have the selected group.
     * Set the server negotiated curve and exit early so a proper keyshare can be generated. */
    if (s2n_is_hello_retry_message(conn)) {
        return S2N_SUCCESS;
    }

    /* Key share not sent by client */
    S2N_ERROR_IF(conn->secure.client_ecc_evp_params[supported_curve_index].evp_pkey == NULL, S2N_ERR_BAD_KEY_SHARE);

    uint16_t share_size;
    S2N_ERROR_IF(s2n_stuffer_data_available(extension) < sizeof(share_size), S2N_ERR_BAD_KEY_SHARE);
    GUARD(s2n_stuffer_read_uint16(extension, &share_size));
    S2N_ERROR_IF(s2n_stuffer_data_available(extension) < share_size, S2N_ERR_BAD_KEY_SHARE);

    /* Proceed to parse share */
    struct s2n_blob point_blob;
    S2N_ERROR_IF(s2n_ecc_evp_read_params_point(extension, share_size,  &point_blob) < 0, S2N_ERR_BAD_KEY_SHARE);
    S2N_ERROR_IF(s2n_ecc_evp_parse_params_point(&point_blob, server_ecc_evp_params) < 0, S2N_ERR_BAD_KEY_SHARE);
    S2N_ERROR_IF(server_ecc_evp_params->evp_pkey == NULL, S2N_ERR_BAD_KEY_SHARE);

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

    uint16_t negotiated_named_group_iana = 0;
    S2N_ERROR_IF(s2n_stuffer_data_available(extension) < sizeof(negotiated_named_group_iana), S2N_ERR_BAD_KEY_SHARE);
    GUARD(s2n_stuffer_read_uint16(extension, &negotiated_named_group_iana));

    const struct s2n_kem_preferences *kem_pref = NULL;
    GUARD(s2n_connection_get_kem_preferences(conn, &kem_pref));
    notnull_check(kem_pref);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    notnull_check(ecc_pref);

    if (s2n_ecc_preferences_includes_curve(ecc_pref, negotiated_named_group_iana)) {
        GUARD(s2n_server_key_share_recv_ecc(conn, negotiated_named_group_iana, extension));
    } else if (s2n_kem_preferences_includes_tls13_kem_group(kem_pref, negotiated_named_group_iana)) {
        GUARD(s2n_server_key_share_recv_pq_hybrid(conn, negotiated_named_group_iana, extension));
    } else {
        S2N_ERROR(S2N_ERR_ECDHE_UNSUPPORTED_CURVE);
    }

    return S2N_SUCCESS;
}

/*
 * Check whether client has sent a corresponding curve and key_share
 */
int s2n_extensions_server_key_share_send_check(struct s2n_connection *conn)
{
    notnull_check(conn);

    /* If we are responding to a retry request then we don't have a valid
     * curve from the client. Just return S2N_SUCCESS so a selected group will be
     * chosen for the key share. */
    if (s2n_is_hello_retry_message(conn)) {
        return S2N_SUCCESS;
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
        GUARD(s2n_set_hello_retry_required(conn));
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
