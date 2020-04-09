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
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_ecc_preferences.h"

#include "utils/s2n_safety.h"

int s2n_extensions_client_supported_groups_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    notnull_check(conn);
    const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
    notnull_check(ecc_pref);

    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SUPPORTED_GROUPS));
    /* size of extension, 2 byte iana ids */
    GUARD(s2n_stuffer_write_uint16(out, 2 + ecc_pref->count * 2));
    /* Curve list len */
    GUARD(s2n_stuffer_write_uint16(out, ecc_pref->count * 2));
    /* Curve list */
    for (int i = 0; i < ecc_pref->count; i++) {
        GUARD(s2n_stuffer_write_uint16(out, ecc_pref->ecc_curves[i]->iana_id));
    }

    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_EC_POINT_FORMATS));
    GUARD(s2n_stuffer_write_uint16(out, 2));
    /* Point format list len */
    GUARD(s2n_stuffer_write_uint8(out, 1));
    /* Only allow uncompressed format */
    GUARD(s2n_stuffer_write_uint8(out, 0));
    
    return 0;
}

int s2n_recv_client_supported_groups(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint16_t size_of_all;
    struct s2n_blob proposed_curves = {0};

    GUARD(s2n_stuffer_read_uint16(extension, &size_of_all));
    if (size_of_all > s2n_stuffer_data_available(extension) || size_of_all % 2) {
        /* Malformed length, ignore the extension */
        return 0;
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
    return 0;
}

int s2n_parse_client_supported_groups_list(struct s2n_connection *conn, struct s2n_blob *iana_ids, const struct s2n_ecc_named_curve **supported_groups) {
    notnull_check(conn->config);
    const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
    notnull_check(ecc_pref);

    struct s2n_stuffer iana_ids_in = {0};

    GUARD(s2n_stuffer_init(&iana_ids_in, iana_ids));
    iana_ids->data = s2n_stuffer_raw_write(&iana_ids_in, iana_ids->size);

    for (int i = 0; i < iana_ids->size / 2; i++) {
        uint16_t iana_id;
        GUARD(s2n_stuffer_read_uint16(&iana_ids_in, &iana_id));
        for (int j = 0; j < ecc_pref->count; j++) {
            const struct s2n_ecc_named_curve *supported_curve = ecc_pref->ecc_curves[j];
            if (supported_curve->iana_id == iana_id) {
                supported_groups[j] = supported_curve;
            }
        }
    }
    return 0;
}

int s2n_choose_supported_group(struct s2n_connection *conn, const struct s2n_ecc_named_curve **group_options, struct s2n_ecc_evp_params *chosen_group)
 {
    notnull_check(conn->config);
    const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
    notnull_check(ecc_pref);

    for (int i = 0; i < ecc_pref->count; i++) {
        if (group_options[i]) {
            chosen_group->negotiated_curve = group_options[i];
            return 0;
        }
    }
    S2N_ERROR(S2N_ERR_ECDHE_UNSUPPORTED_CURVE);
}
