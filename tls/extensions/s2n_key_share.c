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

int s2n_ecdhe_parameters_send(struct s2n_ecc_evp_params *ecc_evp_params, struct s2n_stuffer *out)
{
    notnull_check(out);
    notnull_check(ecc_evp_params);
    notnull_check(ecc_evp_params->negotiated_curve);

    GUARD(s2n_stuffer_write_uint16(out, ecc_evp_params->negotiated_curve->iana_id));
    GUARD(s2n_stuffer_write_uint16(out, ecc_evp_params->negotiated_curve->share_size));

    GUARD(s2n_ecc_evp_generate_ephemeral_key(ecc_evp_params));
    GUARD(s2n_ecc_evp_write_params_point(ecc_evp_params, out));

    return 0;
}
