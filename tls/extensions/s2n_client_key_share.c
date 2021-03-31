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

#include "tls/extensions/s2n_client_key_share.h"
#include "tls/extensions/s2n_key_share.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_kem_preferences.h"

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"
#include "tls/s2n_tls13.h"
#include "pq-crypto/s2n_pq.h"

#define S2N_IS_KEY_SHARE_LIST_EMPTY(preferred_key_shares) (preferred_key_shares & 1)
#define S2N_IS_KEY_SHARE_REQUESTED(preferred_key_shares, i) ((preferred_key_shares >> (i + 1)) & 1)
/**
 * Specified in https://tools.ietf.org/html/rfc8446#section-4.2.8
 * "The "key_share" extension contains the endpoint's cryptographic parameters."
 *
 * Structure:
 * Extension type (2 bytes)
 * Extension data size (2 bytes)
 * Client shares size (2 bytes)
 * Client shares:
 *      Named group (2 bytes)
 *      Key share size (2 bytes)
 *      Key share (variable size)
 *
 * This extension only modifies the connection's client ecc_evp_params. It does
 * not make any decisions about which set of params to use.
 *
 * The server will NOT alert when processing a client extension that violates the RFC.
 * So the server will accept:
 * - Multiple key shares for the same named group. The server will accept the first
 *   key share for the group and ignore any duplicates.
 * - Key shares for named groups not in the client's supported_groups extension.
 **/

static int s2n_client_key_share_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static int s2n_client_key_share_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

const s2n_extension_type s2n_client_key_share_extension = {
    .iana_value = TLS_EXTENSION_KEY_SHARE,
    .minimum_version = S2N_TLS13,
    .is_response = false,
    .send = s2n_client_key_share_send,
    .recv = s2n_client_key_share_recv,
    .should_send = s2n_extension_always_send,
    .if_missing = s2n_extension_noop_if_missing,
};

static int s2n_generate_preferred_ecc_key_shares(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(conn);
    uint8_t preferred_key_shares = conn->preferred_key_shares;
    struct s2n_ecc_evp_params *ecc_evp_params = NULL;

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    POSIX_GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    POSIX_ENSURE_REF(ecc_pref);

    /* If lsb is set, skip keyshare generation for all curve */
    if (S2N_IS_KEY_SHARE_LIST_EMPTY(preferred_key_shares)) {
        return S2N_SUCCESS;
    }

    for (size_t i = 0; i < ecc_pref->count; i++) {
        /* If a bit in the bitmap (minus the lsb) is set, generate keyshare for the corresponding curve */
        if (S2N_IS_KEY_SHARE_REQUESTED(preferred_key_shares, i)) {
            ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
            ecc_evp_params->negotiated_curve = ecc_pref->ecc_curves[i];
            POSIX_GUARD(s2n_ecdhe_parameters_send(ecc_evp_params, out));
        }
    }

    return S2N_SUCCESS;
}

static int s2n_generate_default_ecc_key_share(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(conn);
    const struct s2n_ecc_preferences *ecc_pref = NULL;
    POSIX_GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    POSIX_ENSURE_REF(ecc_pref);

    struct s2n_ecc_evp_params *ecc_evp_params = NULL;
    ecc_evp_params = &conn->secure.client_ecc_evp_params[0];
    ecc_evp_params->negotiated_curve = ecc_pref->ecc_curves[0];
    POSIX_GUARD(s2n_ecdhe_parameters_send(ecc_evp_params, out));

    return S2N_SUCCESS;
}

static int s2n_generate_pq_hybrid_key_share(struct s2n_stuffer *out, struct s2n_kem_group_params *kem_group_params) {
    POSIX_ENSURE_REF(out);
    POSIX_ENSURE_REF(kem_group_params);

    /* This function should never be called when PQ is disabled */
    POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

    const struct s2n_kem_group *kem_group = kem_group_params->kem_group;
    POSIX_ENSURE_REF(kem_group);

    /* The structure of the PQ share is:
     *    IANA ID (2 bytes)
     * || total share size (2 bytes)
     * || size of ECC key share (2 bytes)
     * || ECC key share (variable bytes)
     * || size of PQ key share (2 bytes)
     * || PQ key share (variable bytes) */
    POSIX_GUARD(s2n_stuffer_write_uint16(out, kem_group->iana_id));

    struct s2n_stuffer_reservation total_share_size = {0};
    POSIX_GUARD(s2n_stuffer_reserve_uint16(out, &total_share_size));

    struct s2n_ecc_evp_params *ecc_params = &kem_group_params->ecc_params;
    ecc_params->negotiated_curve = kem_group->curve;
    POSIX_GUARD(s2n_stuffer_write_uint16(out, ecc_params->negotiated_curve->share_size));

    /* If we received a HRR for any reason other than to request a different key share,
     * we might have already generated the key. */
    if (ecc_params->evp_pkey == NULL) {
        POSIX_GUARD(s2n_ecc_evp_generate_ephemeral_key(ecc_params));
    }
    POSIX_GUARD(s2n_ecc_evp_write_params_point(ecc_params, out));

    struct s2n_kem_params *kem_params = &kem_group_params->kem_params;
    kem_params->kem = kem_group->kem;
    POSIX_GUARD(s2n_kem_send_public_key(out, kem_params));

    POSIX_GUARD(s2n_stuffer_write_vector_size(&total_share_size));

    return S2N_SUCCESS;
}

static int s2n_generate_default_pq_hybrid_key_share(struct s2n_connection *conn, struct s2n_stuffer *out) {
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(out);

    /* Client should skip sending PQ groups/key shares if PQ is disabled */
    if (!s2n_pq_is_enabled()) {
        return S2N_SUCCESS;
    }

    const struct s2n_kem_preferences *kem_pref = NULL;
    POSIX_GUARD(s2n_connection_get_kem_preferences(conn, &kem_pref));
    POSIX_ENSURE_REF(kem_pref);

    if (kem_pref->tls13_kem_group_count == 0) {
        return S2N_SUCCESS;
    }

    /* We only send a single PQ key share - the highest preferred one */
    struct s2n_kem_group_params *kem_group_params = &conn->secure.client_kem_group_params[0];
    kem_group_params->kem_group = kem_pref->tls13_kem_groups[0];

    POSIX_GUARD(s2n_generate_pq_hybrid_key_share(out, kem_group_params));

    return S2N_SUCCESS;
}

static int s2n_send_hrr_ecc_keyshare(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(conn);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    POSIX_GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    POSIX_ENSURE_REF(ecc_pref);

    const struct s2n_ecc_named_curve *server_negotiated_curve = conn->secure.server_ecc_evp_params.negotiated_curve;
    POSIX_ENSURE(server_negotiated_curve != NULL, S2N_ERR_BAD_KEY_SHARE);
    POSIX_ENSURE(s2n_ecc_preferences_includes_curve(ecc_pref, server_negotiated_curve->iana_id),
            S2N_ERR_INVALID_HELLO_RETRY);

    struct s2n_ecc_evp_params *ecc_evp_params = NULL;
    for (size_t i = 0; i < ecc_pref->count; i++) {
        if (ecc_pref->ecc_curves[i]->iana_id == server_negotiated_curve->iana_id) {
            ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
            break;
        }
    }
    POSIX_ENSURE_REF(ecc_evp_params);

    /* Generate the keyshare for the server negotiated curve */
    ecc_evp_params->negotiated_curve = server_negotiated_curve;
    POSIX_GUARD(s2n_ecdhe_parameters_send(ecc_evp_params, out));

    return S2N_SUCCESS;
}

static int s2n_send_hrr_pq_hybrid_keyshare(struct s2n_connection *conn, struct s2n_stuffer *out) {
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(out);

    /* If PQ is disabled, the client should not have sent any PQ IDs
     * in the supported_groups list of the initial ClientHello */
    POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

    const struct s2n_kem_preferences *kem_pref = NULL;
    POSIX_GUARD(s2n_connection_get_kem_preferences(conn, &kem_pref));
    POSIX_ENSURE_REF(kem_pref);

    const struct s2n_kem_group *server_negotiated_kem_group = conn->secure.server_kem_group_params.kem_group;
    POSIX_ENSURE(server_negotiated_kem_group != NULL, S2N_ERR_INVALID_HELLO_RETRY);
    POSIX_ENSURE(s2n_kem_preferences_includes_tls13_kem_group(kem_pref, server_negotiated_kem_group->iana_id),
            S2N_ERR_INVALID_HELLO_RETRY);
    struct s2n_kem_group_params *kem_group_params = NULL;

    for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
        if (kem_pref->tls13_kem_groups[i]->iana_id == server_negotiated_kem_group->iana_id) {
            kem_group_params = &conn->secure.client_kem_group_params[i];
            break;
        }
    }
    POSIX_ENSURE_REF(kem_group_params);

    /* Generate the keyshare for the server negotiated KEM group */
    kem_group_params->kem_group = server_negotiated_kem_group;
    POSIX_GUARD(s2n_generate_pq_hybrid_key_share(out, kem_group_params));

    return S2N_SUCCESS;
}

/* From https://tools.ietf.org/html/rfc8446#section-4.1.2
 * If a "key_share" extension was supplied in the HelloRetryRequest,
 * replace the list of shares with a list containing a single
 * KeyShareEntry from the indicated group.*/
static int s2n_send_hrr_keyshare(struct s2n_connection *conn, struct s2n_stuffer *out) {
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(out);

    if (conn->secure.server_kem_group_params.kem_group != NULL) {
        POSIX_GUARD(s2n_send_hrr_pq_hybrid_keyshare(conn, out));
    } else {
        POSIX_GUARD(s2n_send_hrr_ecc_keyshare(conn, out));
    }

    return S2N_SUCCESS;
}

static int s2n_ecdhe_supported_curves_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    if (!conn->preferred_key_shares) {
        POSIX_GUARD(s2n_generate_default_ecc_key_share(conn, out));
        return S2N_SUCCESS;
    }

    POSIX_GUARD(s2n_generate_preferred_ecc_key_shares(conn, out));
    return S2N_SUCCESS;
}

static int s2n_client_key_share_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    struct s2n_stuffer_reservation shares_size = {0};
    POSIX_GUARD(s2n_stuffer_reserve_uint16(out, &shares_size));

    if (s2n_is_hello_retry_handshake(conn)) {
        POSIX_GUARD(s2n_send_hrr_keyshare(conn, out));
    } else {
        POSIX_GUARD(s2n_generate_default_pq_hybrid_key_share(conn, out));
        POSIX_GUARD(s2n_ecdhe_supported_curves_send(conn, out));
    }

    POSIX_GUARD(s2n_stuffer_write_vector_size(&shares_size));

    return S2N_SUCCESS;
}

static int s2n_client_key_share_parse_ecc(struct s2n_stuffer *key_share, const struct s2n_ecc_named_curve *curve,
        struct s2n_ecc_evp_params *ecc_params) {
    POSIX_ENSURE_REF(key_share);
    POSIX_ENSURE_REF(curve);
    POSIX_ENSURE_REF(ecc_params);

    struct s2n_blob point_blob = { 0 };
    POSIX_GUARD(s2n_ecc_evp_read_params_point(key_share, curve->share_size, &point_blob));

    /* Ignore curves with points we can't parse */
    ecc_params->negotiated_curve = curve;
    if (s2n_ecc_evp_parse_params_point(&point_blob, ecc_params) != S2N_SUCCESS) {
        ecc_params->negotiated_curve = NULL;
        POSIX_GUARD(s2n_ecc_evp_params_free(ecc_params));
    }

    return S2N_SUCCESS;
}

static int s2n_client_key_share_recv_ecc(struct s2n_connection *conn, struct s2n_stuffer *key_share,
        uint16_t curve_iana_id, bool *match) {
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(key_share);
    POSIX_ENSURE_REF(match);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    POSIX_GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    POSIX_ENSURE_REF(ecc_pref);

    const struct s2n_ecc_named_curve *curve = NULL;
    struct s2n_ecc_evp_params *client_ecc_params = NULL;
    for (size_t i = 0; i < ecc_pref->count; i++) {
        if (curve_iana_id == ecc_pref->ecc_curves[i]->iana_id) {
            curve = ecc_pref->ecc_curves[i];
            client_ecc_params = &conn->secure.client_ecc_evp_params[i];
            break;
        }
    }

    /* Ignore unsupported curves */
    if (!curve || !client_ecc_params) {
        return S2N_SUCCESS;
    }

    /* Ignore curves that we've already received material for */
    if (client_ecc_params->negotiated_curve) {
        return S2N_SUCCESS;
    }

    /* Ignore curves with unexpected share sizes */
    if (key_share->blob.size != curve->share_size) {
        return S2N_SUCCESS;
    }

    POSIX_GUARD(s2n_client_key_share_parse_ecc(key_share, curve, client_ecc_params));
    /* negotiated_curve will be non-NULL if the key share was parsed successfully */
    if (client_ecc_params->negotiated_curve) {
        *match = true;
    }

    return S2N_SUCCESS;
}

static int s2n_client_key_share_recv_pq_hybrid(struct s2n_connection *conn, struct s2n_stuffer *key_share,
        uint16_t kem_group_iana_id, bool *match) {
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(key_share);
    POSIX_ENSURE_REF(match);

    const struct s2n_kem_preferences *kem_pref = NULL;
    POSIX_GUARD(s2n_connection_get_kem_preferences(conn, &kem_pref));
    POSIX_ENSURE_REF(kem_pref);

    /* Ignore key share if PQ is not enabled */
    if (!s2n_pq_is_enabled()) {
        return S2N_SUCCESS;
    }

    const struct s2n_kem_group *kem_group = NULL;
    struct s2n_kem_group_params *client_kem_group_params = NULL;
    for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
        if (kem_group_iana_id == kem_pref->tls13_kem_groups[i]->iana_id) {
            kem_group = kem_pref->tls13_kem_groups[i];
            client_kem_group_params = &conn->secure.client_kem_group_params[i];
            break;
        }
    }

    /* Ignore unsupported KEM groups */
    if (!kem_group || !client_kem_group_params) {
        return S2N_SUCCESS;
    }

    /* Ignore KEM groups that we've already received material for */
    if (client_kem_group_params->kem_group) {
        return S2N_SUCCESS;
    }

    /* Ignore KEM groups with unexpected overall total share sizes */
    if (key_share->blob.size != kem_group->client_share_size) {
        return S2N_SUCCESS;
    }

    uint16_t ec_share_size = 0;
    POSIX_GUARD(s2n_stuffer_read_uint16(key_share, &ec_share_size));
    /* Ignore KEM groups with unexpected ECC share sizes */
    if (ec_share_size != kem_group->curve->share_size) {
        return S2N_SUCCESS;
    }

    POSIX_GUARD(s2n_client_key_share_parse_ecc(key_share, kem_group->curve, &client_kem_group_params->ecc_params));
    /* If we were unable to parse the EC portion of the share, negotiated_curve
     * will be NULL, and we should ignore the entire key share. */
    if (!client_kem_group_params->ecc_params.negotiated_curve) {
        return S2N_SUCCESS;
    }

    /* Note: the PQ share size is validated in s2n_kem_recv_public_key() */
    /* Ignore groups with PQ public keys we can't parse */
    client_kem_group_params->kem_params.kem = kem_group->kem;
    if (s2n_kem_recv_public_key(key_share, &client_kem_group_params->kem_params) != S2N_SUCCESS) {
        client_kem_group_params->kem_group = NULL;
        client_kem_group_params->kem_params.kem = NULL;
        client_kem_group_params->ecc_params.negotiated_curve = NULL;
        /* s2n_kem_group_free() will free both the ECC and KEM params */
        POSIX_GUARD(s2n_kem_group_free(client_kem_group_params));
        return S2N_SUCCESS;
    }

    client_kem_group_params->kem_group = kem_group;
    *match = true;
    return S2N_SUCCESS;
}

static int s2n_client_key_share_recv(struct s2n_connection *conn, struct s2n_stuffer *extension) {
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(extension);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    POSIX_GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    POSIX_ENSURE_REF(ecc_pref);

    const struct s2n_kem_preferences *kem_pref = NULL;
    POSIX_GUARD(s2n_connection_get_kem_preferences(conn, &kem_pref));
    POSIX_ENSURE_REF(kem_pref);

    uint16_t key_shares_size;
    POSIX_GUARD(s2n_stuffer_read_uint16(extension, &key_shares_size));
    POSIX_ENSURE(s2n_stuffer_data_available(extension) >= key_shares_size, S2N_ERR_BAD_MESSAGE);

    uint16_t named_group, share_size;
    bool match_found = false;
    /* bytes_processed is declared as a uint32_t to avoid integer overflow in later calculations */
    uint32_t bytes_processed = 0;

    while (bytes_processed < key_shares_size) {
        POSIX_GUARD(s2n_stuffer_read_uint16(extension, &named_group));
        POSIX_GUARD(s2n_stuffer_read_uint16(extension, &share_size));

        POSIX_ENSURE(s2n_stuffer_data_available(extension) >= share_size, S2N_ERR_BAD_MESSAGE);
        bytes_processed += share_size + S2N_SIZE_OF_NAMED_GROUP + S2N_SIZE_OF_KEY_SHARE_SIZE;

        struct s2n_blob key_share_blob = { .size = share_size, .data = s2n_stuffer_raw_read(extension, share_size) };
        POSIX_ENSURE_REF(key_share_blob.data);
        struct s2n_stuffer key_share = { 0 };
        POSIX_GUARD(s2n_stuffer_init(&key_share, &key_share_blob));
        POSIX_GUARD(s2n_stuffer_skip_write(&key_share, share_size));

        /* Try to parse the share as ECC, then as PQ/hybrid; will ignore
         * shares for unrecognized groups. */
        POSIX_GUARD(s2n_client_key_share_recv_ecc(conn, &key_share, named_group, &match_found));
        POSIX_GUARD(s2n_client_key_share_recv_pq_hybrid(conn, &key_share, named_group, &match_found));
    }

    /* If there were no matching key shares, then we received an empty key share extension
     * or we didn't match a key share with a supported group. We should send a retry. */
    if (!match_found) {
        POSIX_GUARD(s2n_set_hello_retry_required(conn));
    }

    return S2N_SUCCESS;
}

/* Old-style extension functions -- remove after extensions refactor is complete */

uint32_t s2n_extensions_client_key_share_size(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    POSIX_GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    POSIX_ENSURE_REF(ecc_pref);

    uint32_t s2n_client_key_share_extension_size = S2N_SIZE_OF_EXTENSION_TYPE
            + S2N_SIZE_OF_EXTENSION_DATA_SIZE
            + S2N_SIZE_OF_CLIENT_SHARES_SIZE;

    s2n_client_key_share_extension_size += S2N_SIZE_OF_KEY_SHARE_SIZE + S2N_SIZE_OF_NAMED_GROUP;
    s2n_client_key_share_extension_size += ecc_pref->ecc_curves[0]->share_size;

    return s2n_client_key_share_extension_size;
}

int s2n_extensions_client_key_share_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    return s2n_extension_send(&s2n_client_key_share_extension, conn, out);
}

int s2n_extensions_client_key_share_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    return s2n_extension_recv(&s2n_client_key_share_extension, conn, extension);
}
