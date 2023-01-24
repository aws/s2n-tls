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

#include "utils/s2n_random.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"
#include "s2n_pq_random.h"

static S2N_RESULT s2n_get_random_bytes_default(uint8_t *buffer, uint32_t num_bytes);

static s2n_get_random_bytes_callback s2n_get_random_bytes_cb = s2n_get_random_bytes_default;

S2N_RESULT s2n_get_random_bytes(uint8_t *buffer, uint32_t num_bytes) {
    RESULT_ENSURE_REF(buffer);
    RESULT_GUARD(s2n_get_random_bytes_cb(buffer, num_bytes));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_get_random_bytes_default(uint8_t *buffer, uint32_t num_bytes) {
    struct s2n_blob out = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&out, buffer, num_bytes));
    RESULT_GUARD(s2n_get_private_random_data(&out));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_set_rand_bytes_callback_for_testing(s2n_get_random_bytes_callback rand_bytes_callback) {
    RESULT_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);

    s2n_get_random_bytes_cb = rand_bytes_callback;

    return S2N_RESULT_OK;
}
