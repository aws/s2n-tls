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

static int s2n_server_key_share_generate_pq_hybrid(struct s2n_connection *conn, struct s2n_stuffer *out) {
    notnull_check(out);
    notnull_check(conn);

    ENSURE_POSIX(s2n_is_in_fips_mode() == false, S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS);

    struct s2n_kem_group_params *server_kem_group_params = &conn->secure.server_kem_group_params;

    notnull_check(server_kem_group_params->kem_group);
    GUARD(s2n_stuffer_write_uint16(out, server_kem_group_params->kem_group->iana_id));

    struct s2n_stuffer_reservation total_share_size = { 0 };
    GUARD(s2n_stuffer_reserve_uint16(out, &total_share_size));

    struct s2n_ecc_evp_params *server_ecc_params = &server_kem_group_params->ecc_params;
    notnull_check(server_ecc_params->negotiated_curve);
    GUARD(s2n_stuffer_write_uint16(out, server_ecc_params->negotiated_curve->share_size));
    GUARD(s2n_ecc_evp_generate_ephemeral_key(server_ecc_params));
    GUARD(s2n_ecc_evp_write_params_point(server_ecc_params, out));

    notnull_check(conn->secure.chosen_client_kem_group_params);
    struct s2n_kem_params *client_kem_params = &conn->secure.chosen_client_kem_group_params->kem_params;
    notnull_check(client_kem_params->public_key.data);
    /* s2n_kem_send_ciphertext() will generate the PQ shared secret and use
     * the client's public key to encapsulate; the PQ shared secret will be
     * stored in client_kem_params, and will be used during the hybrid shared
     * secret derivation. */
    GUARD(s2n_kem_send_ciphertext(out, client_kem_params));

    GUARD(s2n_stuffer_write_vector_size(&total_share_size));
    return S2N_SUCCESS;
}

/* Check that client has sent a corresponding key share for the server's KEM group */
int s2n_server_key_share_send_check_pq_hybrid(struct s2n_connection *conn) {
    notnull_check(conn);

    ENSURE_POSIX(s2n_is_in_fips_mode() == false, S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS);

    notnull_check(conn->secure.server_kem_group_params.kem_group);
    notnull_check(conn->secure.server_kem_group_params.kem_params.kem);
    notnull_check(conn->secure.server_kem_group_params.ecc_params.negotiated_curve);

    const struct s2n_kem_group *server_kem_group = conn->secure.server_kem_group_params.kem_group;

    const struct s2n_kem_preferences *kem_pref = NULL;
    GUARD(s2n_connection_get_kem_preferences(conn, &kem_pref));
    notnull_check(kem_pref);

    ENSURE_POSIX(s2n_kem_preferences_includes_tls13_kem_group(kem_pref, server_kem_group->iana_id),
            S2N_ERR_KEM_UNSUPPORTED_PARAMS);

    struct s2n_kem_group_params *client_params = conn->secure.chosen_client_kem_group_params;
    notnull_check(client_params);

    ENSURE_POSIX(client_params->kem_group == server_kem_group, S2N_ERR_BAD_KEY_SHARE);

    ENSURE_POSIX(client_params->ecc_params.negotiated_curve == server_kem_group->curve, S2N_ERR_BAD_KEY_SHARE);
    ENSURE_POSIX(client_params->ecc_params.evp_pkey != NULL, S2N_ERR_BAD_KEY_SHARE);

    ENSURE_POSIX(client_params->kem_params.kem == server_kem_group->kem, S2N_ERR_BAD_KEY_SHARE);
    ENSURE_POSIX(client_params->kem_params.public_key.size == server_kem_group->kem->public_key_length, S2N_ERR_BAD_KEY_SHARE);
    ENSURE_POSIX(client_params->kem_params.public_key.data != NULL, S2N_ERR_BAD_KEY_SHARE);

    return S2N_SUCCESS;
}

/* Check that client has sent a corresponding key share for the server's EC curve */
int s2n_server_key_share_send_check_ecdhe(struct s2n_connection *conn) {
    notnull_check(conn);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    notnull_check(ecc_pref);

    const struct s2n_ecc_named_curve *server_curve = conn->secure.server_ecc_evp_params.negotiated_curve;
    notnull_check(server_curve);

    struct s2n_ecc_evp_params *client_params = NULL;
    for (size_t i = 0; i < ecc_pref->count; i++) {
        if (server_curve == ecc_pref->ecc_curves[i]) {
            client_params = &conn->secure.client_ecc_evp_params[i];
            break;
        }
    }

    notnull_check(client_params);
    ENSURE_POSIX(client_params->negotiated_curve == server_curve, S2N_ERR_BAD_KEY_SHARE);
    ENSURE_POSIX(client_params->evp_pkey != NULL, S2N_ERR_BAD_KEY_SHARE);

    return S2N_SUCCESS;
}

static int s2n_server_key_share_send(struct s2n_connection *conn, struct s2n_stuffer *out) {
    notnull_check(conn);
    notnull_check(out);

    const struct s2n_ecc_named_curve *curve = conn->secure.server_ecc_evp_params.negotiated_curve;
    const struct s2n_kem_group *kem_group = conn->secure.server_kem_group_params.kem_group;

    /* Boolean XOR: exactly one of {server_curve, server_kem_group} should be non-null. */
    ENSURE_POSIX((curve == NULL) != (kem_group == NULL), S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

    /* Retry requests only require the selected named group, not an actual share.
     * https://tools.ietf.org/html/rfc8446#section-4.2.8 */
    if (s2n_is_hello_retry_message(conn)) {
        uint16_t named_group_id;
        if (curve != NULL) {
            named_group_id = curve->iana_id;
        } else {
            named_group_id = kem_group->iana_id;
        }

        GUARD(s2n_stuffer_write_uint16(out, named_group_id));
        return S2N_SUCCESS;
    }

    if (curve != NULL) {
        GUARD(s2n_server_key_share_send_check_ecdhe(conn));
        GUARD(s2n_ecdhe_parameters_send(&conn->secure.server_ecc_evp_params, out));
    } else {
        GUARD(s2n_server_key_share_send_check_pq_hybrid(conn));
        GUARD(s2n_server_key_share_generate_pq_hybrid(conn, out));
    }

    return S2N_SUCCESS;
}

static int s2n_server_key_share_recv_pq_hybrid(struct s2n_connection *conn, uint16_t named_group_iana,
        struct s2n_stuffer *extension) {
    notnull_check(conn);
    notnull_check(extension);

    /* If in FIPS mode, the client should not have sent any PQ IDs
     * in the supported_groups list of the initial ClientHello */
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

    /* If this a HRR, the server will only have sent the named group ID. We assign the
     * appropriate KEM group params above, then exit early so that the client can
     * generate the correct key share. */
    if (s2n_is_hello_retry_message(conn)) {
        return S2N_SUCCESS;
    }

    /* Ensure that the server's key share corresponds with a key share previously sent by the client */
    ENSURE_POSIX(conn->secure.client_kem_group_params[kem_group_index].kem_params.private_key.data != NULL,
                 S2N_ERR_BAD_KEY_SHARE);
    ENSURE_POSIX(conn->secure.client_kem_group_params[kem_group_index].ecc_params.evp_pkey != NULL,
            S2N_ERR_BAD_KEY_SHARE);
    notnull_check(conn->secure.client_kem_group_params[kem_group_index].kem_group);
    eq_check(conn->secure.client_kem_group_params[kem_group_index].kem_group->iana_id, named_group_iana);
    conn->secure.chosen_client_kem_group_params = &conn->secure.client_kem_group_params[kem_group_index];

    uint16_t received_total_share_size;
    GUARD(s2n_stuffer_read_uint16(extension, &received_total_share_size));
    ENSURE_POSIX(received_total_share_size == server_kem_group_params->kem_group->server_share_size, S2N_ERR_BAD_KEY_SHARE);
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

/* Selects highest priority mutually supported key share, or indicates need for HRR */
int s2n_extensions_server_key_share_select(struct s2n_connection *conn) {
    notnull_check(conn);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    notnull_check(ecc_pref);

    const struct s2n_kem_preferences *kem_pref = NULL;
    GUARD(s2n_connection_get_kem_preferences(conn, &kem_pref));
    notnull_check(kem_pref);

    /* Boolean XOR check. When receiving the supported_groups extension, s2n server
     * should (exclusively) set either server_curve or server_kem_group based on the
     * set of mutually supported groups. If both server_curve and server_kem_group
     * are NULL, it is because client and server do not share any mutually supported
     * groups; key negotiation is not possible and the handshake should be aborted
     * without sending HRR. (The case of both being non-NULL should never occur, and
     * is an error.) */
    const struct s2n_ecc_named_curve *server_curve = conn->secure.server_ecc_evp_params.negotiated_curve;
    const struct s2n_kem_group *server_kem_group = conn->secure.server_kem_group_params.kem_group;
    ENSURE_POSIX((server_curve == NULL) != (server_kem_group == NULL), S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

    /* To avoid extra round trips, we prefer to negotiate a group for which we have already
     * received a key share (even if it is different than the group previously chosen). In
     * general, we prefer to negotiate PQ over ECDHE; however, if both client and server
     * support PQ, but the client sent only EC key shares, then we will negotiate ECHDE. */
    for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
        if (conn->secure.mutually_supported_kem_groups[i] && conn->secure.client_kem_group_params[i].kem_group) {
            notnull_check(conn->secure.client_kem_group_params[i].ecc_params.negotiated_curve);
            notnull_check(conn->secure.client_kem_group_params[i].kem_params.kem);

            conn->secure.server_kem_group_params.kem_group = conn->secure.client_kem_group_params[i].kem_group;
            conn->secure.server_kem_group_params.ecc_params.negotiated_curve = conn->secure.client_kem_group_params[i].ecc_params.negotiated_curve;
            conn->secure.server_kem_group_params.kem_params.kem = conn->secure.client_kem_group_params[i].kem_params.kem;
            conn->secure.chosen_client_kem_group_params = &conn->secure.client_kem_group_params[i];

            conn->secure.server_ecc_evp_params.negotiated_curve = NULL;
            return S2N_SUCCESS;
        }
    }

    for (size_t i = 0; i < ecc_pref->count; i++) {
        if (conn->secure.mutually_supported_curves[i] && conn->secure.client_ecc_evp_params[i].negotiated_curve) {
            conn->secure.server_ecc_evp_params.negotiated_curve = conn->secure.client_ecc_evp_params[i].negotiated_curve;

            conn->secure.server_kem_group_params.kem_group = NULL;
            conn->secure.server_kem_group_params.ecc_params.negotiated_curve = NULL;
            conn->secure.server_kem_group_params.kem_params.kem = NULL;
            conn->secure.chosen_client_kem_group_params = NULL;
            return S2N_SUCCESS;
        }
    }

    /* Server and client have mutually supported groups, but the client did not send key
     * shares for any of them. Send HRR indicating the server's preference. */
    GUARD(s2n_set_hello_retry_required(conn));
    return S2N_SUCCESS;
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
