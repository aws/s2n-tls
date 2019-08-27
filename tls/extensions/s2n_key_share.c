/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/extensions/s2n_key_share.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

/* Table to translate iana ids to supported curve index */
static const struct s2n_ecc_named_curve *s2n_iana_id_to_supported_curve[] = {
    [TLS_EC_CURVE_SECP_256_R1] = &s2n_ecc_supported_curves[S2N_ECC_NAMED_CURVED_SECP_256_R1],
    [TLS_EC_CURVE_SECP_384_R1] = &s2n_ecc_supported_curves[S2N_ECC_NAMED_CURVED_SECP_384_R1],
};

int s2n_ecdhe_parameters_send(struct s2n_ecc_params *ecc_params, struct s2n_stuffer *out)
{
    notnull_check(out);
    notnull_check(ecc_params);
    notnull_check(ecc_params->negotiated_curve);

    GUARD(s2n_stuffer_write_uint16(out, ecc_params->negotiated_curve->iana_id));
    GUARD(s2n_stuffer_write_uint16(out, ecc_params->negotiated_curve->share_size));

    GUARD(s2n_ecc_generate_ephemeral_key(ecc_params));
    GUARD(s2n_ecc_write_ecc_params_point(ecc_params, out));

    return 0;
}

const struct s2n_ecc_named_curve* s2n_ecc_find_supported_curve_by_iana_id(uint16_t named_group)
{
    if (named_group >= s2n_array_len(s2n_iana_id_to_supported_curve)) {
        return NULL;
    }

    return s2n_iana_id_to_supported_curve[named_group];
}
