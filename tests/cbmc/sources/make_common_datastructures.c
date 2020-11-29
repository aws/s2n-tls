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

#include <cbmc_proof/make_common_datastructures.h>

bool s2n_blob_is_bounded(const struct s2n_blob *blob, const size_t max_size) { return (blob->size <= max_size); }

bool s2n_stuffer_is_bounded(const struct s2n_stuffer *stuffer, const size_t max_size)
{
    return (stuffer->blob.size <= max_size);
}

void ensure_s2n_blob_has_allocated_fields(struct s2n_blob *blob)
{
    if (blob->growable) {
        blob->data = (blob->allocated == 0) ? NULL : bounded_malloc(blob->allocated);
    } else {
        blob->data = (blob->size == 0) ? NULL : bounded_malloc(blob->size);
    }
}

struct s2n_blob *cbmc_allocate_s2n_blob()
{
    struct s2n_blob *blob = can_fail_malloc(sizeof(*blob));
    if (blob != NULL) { ensure_s2n_blob_has_allocated_fields(blob); }
    return blob;
}

void ensure_s2n_stuffer_has_allocated_fields(struct s2n_stuffer *stuffer)
{
    ensure_s2n_blob_has_allocated_fields(&stuffer->blob);
}

struct s2n_stuffer *cbmc_allocate_s2n_stuffer()
{
    struct s2n_stuffer *stuffer = can_fail_malloc(sizeof(*stuffer));
    if (stuffer != NULL) { ensure_s2n_stuffer_has_allocated_fields(stuffer); }
    return stuffer;
}

const char *ensure_c_str_is_allocated(size_t max_size)
{
    size_t cap;
    __CPROVER_assume(cap > 0 && cap <= max_size);
    const char *str = bounded_malloc(cap);
    /* Ensure that its a valid c string. Since all bytes are nondeterminstic, the actual
     * string length is 0..str_cap
     */
    __CPROVER_assume(IMPLIES(str != NULL, str[ cap - 1 ] == '\0'));
    return str;
}

const char *nondet_c_str_is_allocated(size_t max_size)
{
    size_t cap;
    __CPROVER_assume(cap > 0 && cap <= max_size);
    const char *str = can_fail_malloc(cap);
    /* Ensure that its a valid c string. Since all bytes are nondeterminstic, the actual
     * string length is 0..str_cap
     */
    __CPROVER_assume(IMPLIES(str != NULL, str[ cap - 1 ] == 0));
    return str;
}

struct s2n_stuffer_reservation *cbmc_allocate_s2n_stuffer_reservation()
{
    struct s2n_stuffer_reservation *reservation = can_fail_malloc(sizeof(*reservation));
    if (reservation != NULL) { reservation->stuffer = cbmc_allocate_s2n_stuffer(); }
    return reservation;
}

struct s2n_array *cbmc_allocate_s2n_array()
{
    struct s2n_array *array = can_fail_malloc(sizeof(*array));
    if (array != NULL) { ensure_s2n_blob_has_allocated_fields(&array->mem); }
    return array;
}

static int nondet_comparator(const void *a, const void *b)
{
    assert(a != NULL);
    assert(b != NULL);
    return nondet_int();
}

struct s2n_set *cbmc_allocate_s2n_set()
{
    struct s2n_set *set = can_fail_malloc(sizeof(*set));
    if (set != NULL) {
        set->data       = cbmc_allocate_s2n_array();
        set->comparator = nondet_comparator;
    }
    return set;
}

bool s2n_array_is_bounded(const struct s2n_array *array, const size_t max_len, const size_t max_element_size)
{
    return (array->len <= max_len) && (array->element_size <= max_element_size);
}

bool s2n_set_is_bounded(const struct s2n_set *set, const size_t max_len, const size_t max_element_size)
{
    return s2n_array_is_bounded(set->data, max_len, max_element_size);
}

struct s2n_dh_params *cbmc_allocate_dh_params()
{
    struct s2n_dh_params *dh_params = malloc(sizeof(*dh_params));
    if (dh_params != NULL) {
        dh_params->dh = malloc(sizeof(*(dh_params->dh)));
        if (dh_params->dh != NULL) {
            dh_params->dh->pub_key  = malloc(sizeof(*(dh_params->dh->pub_key)));
            dh_params->dh->priv_key = malloc(sizeof(*(dh_params->dh->priv_key)));
            dh_params->dh->p        = malloc(sizeof(*(dh_params->dh->p)));
            dh_params->dh->g        = malloc(sizeof(*(dh_params->dh->g)));
        }
    }
    return dh_params;
}

EVP_MD_CTX* cbmc_allocate_EVP_MD_CTX() {
    EVP_MD_CTX *ctx = malloc(sizeof(*ctx));
    if (ctx != NULL) {
        ctx->digest = malloc(sizeof(*(ctx->digest)));
        ctx->md_data = malloc(EVP_MAX_MD_SIZE);
        ctx->pctx = malloc(sizeof(*(ctx->pctx)));
        if (ctx->pctx != NULL) {
            ctx->pctx->pkey = malloc(sizeof(*(ctx->pctx->pkey)));
            if (ctx->pctx->pkey != NULL) {
                ctx->pctx->pkey->ec_key = malloc(sizeof(*(ctx->pctx->pkey->ec_key)));
                if (ctx->pctx->pkey->ec_key != NULL) {
                    ctx->pctx->pkey->ec_key->group = malloc(sizeof(*(ctx->pctx->pkey->ec_key->group)));
                    if (ctx->pctx->pkey->ec_key->group != NULL) {
                        ctx->pctx->pkey->ec_key->group->order = malloc(sizeof(*(ctx->pctx->pkey->ec_key->group->order)));
                        if (ctx->pctx->pkey->ec_key->group->order != NULL) {
                            ctx->pctx->pkey->ec_key->group->order->d = malloc(sizeof(*(ctx->pctx->pkey->ec_key->group->order->d)));
                        }
                    }
                    ctx->pctx->pkey->ec_key->priv_key = malloc(sizeof(*(ctx->pctx->pkey->ec_key->priv_key)));
                    if (ctx->pctx->pkey->ec_key->priv_key != NULL) {
                        ctx->pctx->pkey->ec_key->priv_key->d = malloc(sizeof(*(ctx->pctx->pkey->ec_key->priv_key->d)));
                    }
                }
            }
        }
    }
    return ctx;
}

struct s2n_hash_state* cbmc_allocate_s2n_hash_state()
{
    struct s2n_hash_state *state = malloc(sizeof(*state));
    if (state != NULL)
    {
        state->hash_impl = malloc(sizeof(*(state->hash_impl)));
        state->digest.high_level.evp.md = malloc(sizeof(*(state->digest.high_level.evp.md)));
        state->digest.high_level.evp.ctx = cbmc_allocate_EVP_MD_CTX();
        state->digest.high_level.evp_md5_secondary.md = malloc(sizeof(*(state->digest.high_level.evp_md5_secondary.md)));
        state->digest.high_level.evp_md5_secondary.ctx = cbmc_allocate_EVP_MD_CTX();
    }
    return state;
}
