/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <assert.h>
#include <crypto/s2n_hash.h>
#include <utils/s2n_mem.h>
#include <cbmc_proof/cbmc_utils.h>

/**
 * CBMC has an internal representation in which each object has an index and a (signed) offset
 * A buffer cannot be larger than the max size of the offset
 * The Makefile is expected to set CBMC_OBJECT_BITS to the value of --object-bits
 */
#define MAX_MALLOC (SIZE_MAX >> (CBMC_OBJECT_BITS + 1))

void assert_stuffer_immutable_fields_after_read(const struct s2n_stuffer *lhs, const struct s2n_stuffer *rhs,
                                                const struct store_byte_from_buffer *stored_byte_from_rhs)
{
    /* In order to be equivalent, either both are NULL or both are non-NULL */
    if (lhs == rhs) {
        return;
    } else {
        assert(lhs && rhs);
    }
    assert(lhs->write_cursor == rhs->write_cursor);
    assert(lhs->high_water_mark == rhs->high_water_mark);
    assert(lhs->alloced == rhs->alloced);
    assert(lhs->growable == rhs->growable);
    assert(lhs->tainted == rhs->tainted);
    assert_blob_equivalence(&lhs->blob, &rhs->blob, stored_byte_from_rhs);
}

void assert_blob_equivalence(const struct s2n_blob *lhs, const struct s2n_blob *rhs,
                             const struct store_byte_from_buffer *stored_byte_from_rhs)
{
    /* In order to be equivalent, either both are NULL or both are non-NULL */
    if (lhs == rhs) {
        return;
    } else {
        assert(lhs && rhs);
    }
    assert(lhs->size == rhs->size);
    assert(lhs->allocated == rhs->allocated);
    assert(lhs->growable == rhs->growable);
    if (lhs->size > 0) { assert_byte_from_blob_matches(lhs, stored_byte_from_rhs); }
}

void assert_stuffer_equivalence(const struct s2n_stuffer *lhs, const struct s2n_stuffer *rhs,
                                const struct store_byte_from_buffer *stored_byte_from_rhs)
{
    /* In order to be equivalent, either both are NULL or both are non-NULL */
    if (lhs == rhs) {
        return;
    } else {
        assert(lhs && rhs);
    }
    assert(lhs->read_cursor == rhs->read_cursor);
    assert(lhs->write_cursor == rhs->write_cursor);
    assert(lhs->high_water_mark == rhs->high_water_mark);
    assert(lhs->alloced == rhs->alloced);
    assert(lhs->growable == rhs->growable);
    assert(lhs->tainted == rhs->tainted);
    assert_blob_equivalence(&lhs->blob, &rhs->blob, stored_byte_from_rhs);
}

void assert_bytes_match(const uint8_t *const a, const uint8_t *const b, const size_t len)
{
    assert(!a == !b);
    if (len > 0 && a != NULL && b != NULL) {
        size_t i;
        __CPROVER_assume(i < len && len < MAX_MALLOC); /* prevent spurious pointer overflows */
        assert(a[ i ] == b[ i ]);
    }
}

void assert_all_bytes_are(const uint8_t *const a, const uint8_t c, const size_t len)
{
    if (len > 0 && a != NULL) {
        size_t i;
        __CPROVER_assume(i < len);
        assert(a[ i ] == c);
    }
}

void assert_all_zeroes(const uint8_t *const a, const size_t len) { assert_all_bytes_are(a, 0, len); }

void assert_byte_from_buffer_matches(const uint8_t *const buffer, const struct store_byte_from_buffer *const b)
{
    if (buffer && b) { assert(*(buffer + b->idx) == b->byte); }
}

void assert_byte_from_blob_matches(const struct s2n_blob *blob, const struct store_byte_from_buffer *const b)
{
    if (blob && blob->size) { assert_byte_from_buffer_matches(blob->data, b); }
}

void save_byte_from_array(const uint8_t *const array, const size_t size, struct store_byte_from_buffer *const storage)
{
    if (size > 0 && array && storage) {
        storage->idx = nondet_size_t();
        __CPROVER_assume(storage->idx < size);
        storage->byte = array[ storage->idx ];
    }
}

void save_byte_from_blob(const struct s2n_blob *blob, struct store_byte_from_buffer *storage)
{
    save_byte_from_array(blob->data, blob->size, storage);
}

int nondet_compare(const void *const a, const void *const b)
{
    assert(a != NULL);
    assert(b != NULL);
    return nondet_int();
}

int __CPROVER_uninterpreted_compare(const void *const a, const void *const b);
bool __CPROVER_uninterpreted_equals(const void *const a, const void *const b);
uint64_t __CPROVER_uninterpreted_hasher(const void *const a);

int uninterpreted_compare(const void *const a, const void *const b)
{
    assert(a != NULL);
    assert(b != NULL);
    int rval = __CPROVER_uninterpreted_compare(a, b);
    /* Compare is reflexive */
    __CPROVER_assume(IMPLIES(a == b, rval == 0));
    /* Compare is anti-symmetric*/
    __CPROVER_assume(__CPROVER_uninterpreted_compare(b, a) == -rval);
    /* If two things are equal, their hashes are also equal */
    if (rval == 0) { __CPROVER_assume(__CPROVER_uninterpreted_hasher(a) == __CPROVER_uninterpreted_hasher(b)); }
    return rval;
}

bool nondet_equals(const void *const a, const void *const b)
{
    assert(a != NULL);
    assert(b != NULL);
    return nondet_bool();
}

/**
 * Add assumptions that equality is reflexive and symmetric. Don't bother with
 * transitivity because it doesn't cause any spurious proof failures on hash-table
 */
bool uninterpreted_equals(const void *const a, const void *const b)
{
    bool rval = __CPROVER_uninterpreted_equals(a, b);
    /* Equals is reflexive */
    __CPROVER_assume(IMPLIES(a == b, rval));
    /* Equals is symmetric */
    __CPROVER_assume(__CPROVER_uninterpreted_equals(b, a) == rval);
    /* If two things are equal, their hashes are also equal */
    if (rval) { __CPROVER_assume(__CPROVER_uninterpreted_hasher(a) == __CPROVER_uninterpreted_hasher(b)); }
    return rval;
}

bool uninterpreted_equals_assert_inputs_nonnull(const void *const a, const void *const b)
{
    assert(a != NULL);
    assert(b != NULL);
    return uninterpreted_equals(a, b);
}

uint64_t nondet_hasher(const void *a)
{
    assert(a != NULL);
    return nondet_uint64_t();
}

/**
 * Standard stub function to hash one item.
 */
uint64_t uninterpreted_hasher(const void *a)
{
    assert(a != NULL);
    return __CPROVER_uninterpreted_hasher(a);
}

bool uninterpreted_predicate_fn(uint8_t value);

void nondet_s2n_mem_init()
{
    if (nondet_bool()) { s2n_mem_init(); }
}

void assert_rc_decrement_on_evp_pkey_ctx(struct rc_keys_from_evp_pkey_ctx *storage)
{
    if (storage->pkey_refs > 1) {
        assert(storage->pkey->references == storage->pkey_refs - 1);
    } else if (storage->pkey_refs == 1 && storage->pkey_eckey_refs > 1) {
        assert(storage->pkey_eckey->references == storage->pkey_eckey_refs - 1);
    }
}

void assert_rc_unchanged_on_evp_pkey_ctx(struct rc_keys_from_evp_pkey_ctx *storage)
{
    if (storage->pkey) {
        assert(storage->pkey->references == storage->pkey_refs);
    }
    if (storage->pkey_eckey) {
        assert(storage->pkey_eckey->references == storage->pkey_eckey_refs);
    }
}

void assert_rc_decrement_on_hash_state(struct rc_keys_from_hash_state *storage)
{
    assert_rc_decrement_on_evp_pkey_ctx(&storage->evp);
    assert_rc_decrement_on_evp_pkey_ctx(&storage->evp_md5);
}

void assert_rc_unchanged_on_hash_state(struct rc_keys_from_hash_state *storage)
{
    assert_rc_unchanged_on_evp_pkey_ctx(&storage->evp);
    assert_rc_unchanged_on_evp_pkey_ctx(&storage->evp_md5);
}

void save_abstract_evp_ctx(const EVP_PKEY_CTX *pctx, struct rc_keys_from_evp_pkey_ctx *storage)
{
    storage->pkey = pctx->pkey;
    if (storage->pkey) {
        storage->pkey_refs = storage->pkey->references;
        storage->pkey_eckey = storage->pkey->ec_key;
        if (storage->pkey_eckey) {
            storage->pkey_eckey_refs = storage->pkey_eckey->references;
        }
    }
}

void save_rc_keys_from_hash_state(const struct s2n_hash_state *state, struct rc_keys_from_hash_state *storage)
{
    storage->evp.pkey = NULL;
    storage->evp.pkey_eckey = NULL;
    storage->evp_md5.pkey = NULL;
    storage->evp_md5.pkey_eckey = NULL;
    storage->evp.pkey_refs = storage->evp.pkey_eckey_refs = storage->evp_md5.pkey_refs = storage->evp_md5.pkey_eckey_refs = 0;

    if (state) {
        if (state->digest.high_level.evp.ctx) {
            if (state->digest.high_level.evp.ctx->pctx) {
                save_abstract_evp_ctx(state->digest.high_level.evp.ctx->pctx, &storage->evp);
            }
        }

        if (state->digest.high_level.evp_md5_secondary.ctx) {
            if (state->digest.high_level.evp_md5_secondary.ctx->pctx) {
                save_abstract_evp_ctx(state->digest.high_level.evp_md5_secondary.ctx->pctx, &storage->evp_md5);
            }
        }
    }
}

void free_rc_keys_from_evp_pkey_ctx(struct rc_keys_from_evp_pkey_ctx *pctx)
{
    if (pctx->pkey && pctx->pkey_refs != 1) {
        pctx->pkey->references = 1;
        EVP_PKEY_free(pctx->pkey);
    }
    if (pctx->pkey_eckey && pctx->pkey_eckey_refs != 1) {
        pctx->pkey_eckey->references = 1;
        EC_KEY_free(pctx->pkey_eckey);
    }
}

void free_rc_keys_from_hash_state(struct rc_keys_from_hash_state *storage)
{
    free_rc_keys_from_evp_pkey_ctx(&storage->evp);
    free_rc_keys_from_evp_pkey_ctx(&storage->evp_md5);
}
