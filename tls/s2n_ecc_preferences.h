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

#pragma once

#include <s2n.h>
#include <strings.h>
#include <stdbool.h>

#include "crypto/s2n_ecc_evp.h"

struct s2n_ecc_preferences {
    uint8_t count;
    const struct s2n_ecc_named_curve *const *ecc_curves;
};
extern const struct s2n_ecc_preferences s2n_ecc_preferences_20140601;
extern const struct s2n_ecc_preferences s2n_ecc_preferences_20200310;
extern const struct s2n_ecc_preferences s2n_ecc_preferences_20201021;
extern const struct s2n_ecc_preferences s2n_ecc_preferences_test_all;
extern const struct s2n_ecc_preferences s2n_ecc_preferences_null;

int s2n_check_ecc_preferences_curves_list(const struct s2n_ecc_preferences *ecc_preferences);
bool s2n_ecc_preferences_includes_curve(const struct s2n_ecc_preferences *ecc_preferences, uint16_t query_iana_id);
