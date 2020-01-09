/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cbmc_proof/nondet.h>
#include <cbmc_proof/proof_allocators.h>
#include <utils/s2n_blob.h>
#include <stddef.h>
#include <stdint.h>

#define IMPLIES(a, b) (!(a) || (b))

struct store_byte_from_buffer {
    size_t index;
    uint8_t byte;
};

/**
 * Asserts whether all bytes from two arrays of same length match.
 */
void assert_bytes_match(const uint8_t *const a, const uint8_t *const b, const size_t len);

/**
 * Asserts whether all bytes from an array are equal to c.
 */
void assert_all_bytes_are(const uint8_t *const a, const uint8_t c, const size_t len);

/**
 * Asserts whether all bytes from an array are equal to 0.
 */
void assert_all_zeroes(const uint8_t *const a, const size_t len);

/**
 * Asserts whether the byte in storage correspond to the byte in the same position in buffer.
 */
void assert_byte_from_buffer_matches(const uint8_t *const buffer, const struct store_byte_from_buffer *const b);

/**
 * Asserts whether the byte in storage correspond to the byte in the same position in buffer.
 */
void assert_byte_from_blob_matches(const struct s2n_blob *blob, const struct store_byte_from_buffer *const b);

/**
 * Nondeterministically selects a byte from array and stores it into a store_array_list_byte
 * structure. Afterwards, one can prove using the assert_byte_from_buffer_matches function
 * whether no byte in the array has changed.
 */
void save_byte_from_array(const uint8_t *const array, const size_t size, struct store_byte_from_buffer *const storage);

/**
 * Nondeterministically selects a byte from blob and stores it into a store_array_list_byte
 * structure. Afterwards, one can prove using the assert_byte_from_blob_matches function
 * whether no byte in the blob has changed.
 */
void save_byte_from_blob(const struct s2n_blob *blob, struct store_byte_from_buffer * storage);

/**
 * Standard stub function to compare two items.
 */
int nondet_compare(const void *const a, const void *const b);

/**
 * Standard stub function to compare two items.
 */
int uninterpreted_compare(const void *const a, const void *const b);

/**
 * Standard stub function to compare two items.
 */
bool nondet_equals(const void *const a, const void *const b);

/**
 * Standard stub function to compare two items.
 * Also enforces uninterpreted_hasher() to be equal for equal values.
 */
bool uninterpreted_equals(const void *const a, const void *const b);

/**
 * uninterpreted_equals(), but with an extra assertion that a and b are both not null
 */
bool uninterpreted_equals_assert_inputs_nonnull(const void *const a, const void *const b);

/**
 * Standard stub function to hash one item.
 */
uint64_t nondet_hasher(const void *a);

/**
 * Standard stub function to hash one item.
 */
uint64_t uninterpreted_hasher(const void *a);

/**
 * Standard stub function of a predicate
 */
bool uninterpreted_predicate_fn(uint8_t value);
