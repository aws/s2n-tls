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

#include <stdint.h>

#include "utils/s2n_blob.h"

#include "crypto/s2n_hmac.h"

extern int s2n_hkdf(struct s2n_hmac_state *hmac, s2n_hmac_algorithm alg, const struct s2n_blob *salt,
                    const struct s2n_blob *key, const struct s2n_blob *info, struct s2n_blob *output);

extern int s2n_hkdf_extract(struct s2n_hmac_state *hmac, s2n_hmac_algorithm alg, const struct s2n_blob *salt,
                            const struct s2n_blob *key, struct s2n_blob *pseudo_rand_key);

extern int s2n_hkdf_expand_label(struct s2n_hmac_state *hmac, s2n_hmac_algorithm alg, const struct s2n_blob *secret, const struct s2n_blob *label,
                                 const struct s2n_blob *context, struct s2n_blob *output);
