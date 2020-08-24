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

#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/proof_allocators.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_array.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_set.h"

/*
 * Checks whether s2n_blob is bounded by max_size.
 */
bool s2n_blob_is_bounded(const struct s2n_blob *blob, const size_t max_size);

/*
 * Checks whether s2n_blob is bounded by max_size.
 */
bool s2n_stuffer_is_bounded(const struct s2n_stuffer *stuffer, const size_t max_size);

/*
 * Ensures s2n_blob has a proper allocated data member.
 */
void ensure_s2n_blob_has_allocated_fields(struct s2n_blob *blob);

/*
 * Properly allocates s2n_blob for CBMC proofs.
 */
struct s2n_blob *cbmc_allocate_s2n_blob();

/*
 * Ensures s2n_stuffer has a proper allocated blob member.
 */
void ensure_s2n_stuffer_has_allocated_fields(struct s2n_stuffer *stuffer);

/*
 * Properly allocates s2n_stuffer for CBMC proofs.
 */
struct s2n_stuffer *cbmc_allocate_s2n_stuffer();

/*
 * Ensures a valid const string is allocated,
 * with as much nondet as possible, len < max_size.
 */
const char *ensure_c_str_is_allocated(size_t max_size);

/*
 * Nondeterministically return a valid-allocated const string or NULL,
 * with as much nondet as possible, len < max_size.
 */
const char *nondet_c_str_is_allocated(size_t max_size);

/*
 * Properly allocates s2n_stuffer_reservation for CBMC proofs.
 */
struct s2n_stuffer_reservation *cbmc_allocate_s2n_stuffer_reservation();

/*
 * Properly allocates s2n_array for CBMC proofs.
 */
struct s2n_array* cbmc_allocate_s2n_array();

/*
 * Properly allocates s2n_set for CBMC proofs.
 */
struct s2n_set* cbmc_allocate_s2n_set();

/*
 * Checks whether s2n_array is bounded by max_len and max_element_size.
 */
bool s2n_array_is_bounded(const struct s2n_array *array, const size_t max_len, const size_t max_element_size);

/*
 * Checks whether s2n_set is bounded by max_len and max_element_size.
 */
bool s2n_set_is_bounded(const struct s2n_set *set, const size_t max_len, const size_t max_element_size);
