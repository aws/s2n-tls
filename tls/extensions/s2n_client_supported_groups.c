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

#include <sys/param.h>
#include <stdint.h>

#include "tls/extensions/s2n_client_supported_groups.h"
#include "tls/extensions/s2n_ec_point_format.h"

#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_security_policies.h"

#include "utils/s2n_safety.h"

static int s2n_client_supported_groups_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static int s2n_client_supported_groups_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

const s2n_extension_type s2n_client_supported_groups_extension = {
    .iana_value = TLS_EXTENSION_SUPPORTED_GROUPS,
    .is_response = false,
    .send = s2n_client_supported_groups_send,
    .recv = s2n_client_supported_groups_recv,
    .should_send = s2n_extension_should_send_if_ecc_enabled,
    .if_missing = s2n_extension_noop_if_missing,
};

int s2n_parse_client_supported_groups_list(struct s2n_connection *conn, struct s2n_blob *iana_ids, const struct s2n_ecc_named_curve **supported_groups);
int s2n_choose_supported_group(struct s2n_connection *conn, const struct s2n_ecc_named_curve **group_options, struct s2n_ecc_evp_params *chosen_group);

bool s2n_extension_should_send_if_ecc_enabled(struct s2n_connection *conn)
{
    const struct s2n_security_policy *security_policy;
    return s2n_connection_get_security_policy(conn, &security_policy) == S2N_SUCCESS
            && s2n_ecc_is_extension_required(security_policy);
}

static int s2n_client_supported_groups_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    notnull_check(conn);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    notnull_check(ecc_pref);

    /* Curve list len */
    GUARD(s2n_stuffer_write_uint16(out, ecc_pref->count * sizeof(uint16_t)));

    /* Curve list */
    for (int i = 0; i < ecc_pref->count; i++) {
        GUARD(s2n_stuffer_write_uint16(out, ecc_pref->ecc_curves[i]->iana_id));
    }

    return S2N_SUCCESS;
}

static int s2n_client_supported_groups_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint16_t size_of_all;
    struct s2n_blob proposed_curves = {0};

    GUARD(s2n_stuffer_read_uint16(extension, &size_of_all));
    if (size_of_all > s2n_stuffer_data_available(extension) || size_of_all % sizeof(uint16_t)) {
        /* Malformed length, ignore the extension */
        return S2N_SUCCESS;
    }

    proposed_curves.size = size_of_all;
    proposed_curves.data = s2n_stuffer_raw_read(extension, proposed_curves.size);
    notnull_check(proposed_curves.data);

    GUARD(s2n_parse_client_supported_groups_list(conn, &proposed_curves, conn->secure.mutually_supported_groups));
    if (s2n_choose_supported_group(conn, conn->secure.mutually_supported_groups,
            &conn->secure.server_ecc_evp_params) != S2N_SUCCESS) {
        /* Can't agree on a curve, ECC is not allowed. Return success to proceed with the handshake. */
        conn->secure.server_ecc_evp_params.negotiated_curve = NULL;
    }

    return S2N_SUCCESS;
}

int s2n_parse_client_supported_groups_list(struct s2n_connection *conn, struct s2n_blob *iana_ids, const struct s2n_ecc_named_curve **supported_groups) {
    notnull_check(conn);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    notnull_check(ecc_pref);

    struct s2n_stuffer iana_ids_in = {0};

    GUARD(s2n_stuffer_init(&iana_ids_in, iana_ids));
    iana_ids->data = s2n_stuffer_raw_write(&iana_ids_in, iana_ids->size);

    uint16_t iana_id;
    for (int i = 0; i < iana_ids->size / sizeof(iana_id); i++) {
        GUARD(s2n_stuffer_read_uint16(&iana_ids_in, &iana_id));
        for (int j = 0; j < ecc_pref->count; j++) {
            const struct s2n_ecc_named_curve *supported_curve = ecc_pref->ecc_curves[j];
            if (supported_curve->iana_id == iana_id) {
                supported_groups[j] = supported_curve;
            }
        }
    }
    return S2N_SUCCESS;
}

int s2n_choose_supported_group(struct s2n_connection *conn, const struct s2n_ecc_named_curve **group_options, struct s2n_ecc_evp_params *chosen_group)
 {
    notnull_check(conn);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    notnull_check(ecc_pref);

    for (int i = 0; i < ecc_pref->count; i++) {
        if (group_options[i]) {
            chosen_group->negotiated_curve = group_options[i];
            return S2N_SUCCESS;
        }
    }

    S2N_ERROR(S2N_ERR_ECDHE_UNSUPPORTED_CURVE);
}

/* Old-style extension functions -- remove after extensions refactor is complete */

int s2n_extensions_client_supported_groups_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    GUARD(s2n_extension_send(&s2n_client_supported_groups_extension, conn, out));

    /* The original send method also sent ec point formats. To avoid breaking
     * anything, I'm going to let it continue writing point formats.
     */
    GUARD(s2n_extension_send(&s2n_client_ec_point_format_extension, conn, out));

    return S2N_SUCCESS;
}

int s2n_recv_client_supported_groups(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    return s2n_extension_recv(&s2n_client_supported_groups_extension, conn, extension);
}
