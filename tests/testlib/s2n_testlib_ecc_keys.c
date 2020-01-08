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

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

#include "testlib/s2n_testlib.h"

int s2n_public_ecc_keys_are_equal(struct s2n_ecc_evp_params *params_1, struct s2n_ecc_evp_params *params_2)
{
    notnull_check(params_1);
    notnull_check(params_2);

    struct s2n_stuffer point_stuffer;
    int size = params_1->negotiated_curve->share_size;

    if (params_1->negotiated_curve != params_2->negotiated_curve) {
        return 0;
    }

    GUARD(s2n_stuffer_alloc(&point_stuffer, size * 2));

    uint8_t *point_1 = s2n_stuffer_raw_write(&point_stuffer, 0);
    GUARD(s2n_ecc_evp_write_params_point(params_1, &point_stuffer));

    uint8_t *point_2 = s2n_stuffer_raw_write(&point_stuffer, 0);
    GUARD(s2n_ecc_evp_write_params_point(params_2, &point_stuffer));

    int result = memcmp(point_1, point_2, size) == 0;

    GUARD(s2n_stuffer_free(&point_stuffer));

    return result;
}
