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

#include "tls/s2n_fingerprint.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

static S2N_RESULT s2n_fingerprint_init(struct s2n_fingerprint *fingerprint,
        s2n_fingerprint_type type)
{
    RESULT_ENSURE_REF(fingerprint);

    switch (type) {
        case S2N_FINGERPRINT_JA3:
            fingerprint->method = &ja3_fingerprint;
            break;
        default:
            RESULT_BAIL(S2N_ERR_INVALID_ARGUMENT);
    }

    const struct s2n_fingerprint_method *method = fingerprint->method;
    RESULT_ENSURE_REF(method);
    RESULT_GUARD_POSIX(s2n_hash_new(&fingerprint->hash));
    s2n_hash_allow_md5_for_fips(&fingerprint->hash);
    RESULT_GUARD_POSIX(s2n_hash_init(&fingerprint->hash, method->hash));
    return S2N_RESULT_OK;
}

struct s2n_fingerprint *s2n_fingerprint_new(s2n_fingerprint_type type)
{
    DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
    PTR_GUARD_POSIX(s2n_alloc(&mem, sizeof(struct s2n_fingerprint)));
    PTR_GUARD_POSIX(s2n_blob_zero(&mem));
    struct s2n_fingerprint *fingerprint = (struct s2n_fingerprint *) (void *) mem.data;
    PTR_ENSURE_REF(fingerprint);
    PTR_GUARD_RESULT(s2n_fingerprint_init(fingerprint, type));
    ZERO_TO_DISABLE_DEFER_CLEANUP(mem);
    return fingerprint;
}

static S2N_CLEANUP_RESULT s2n_fingerprint_free_fields(struct s2n_fingerprint *fingerprint)
{
    if (!fingerprint) {
        return S2N_RESULT_OK;
    }
    RESULT_GUARD_POSIX(s2n_hash_free(&fingerprint->hash));
    return S2N_RESULT_OK;
}

int s2n_fingerprint_free(struct s2n_fingerprint **fingerprint_ptr)
{
    if (!fingerprint_ptr) {
        return S2N_SUCCESS;
    }
    POSIX_GUARD_RESULT(s2n_fingerprint_free_fields(*fingerprint_ptr));
    POSIX_GUARD(s2n_free_object((uint8_t **) (void **) fingerprint_ptr,
            sizeof(struct s2n_fingerprint)));
    return S2N_SUCCESS;
}

int s2n_fingerprint_wipe(struct s2n_fingerprint *fingerprint)
{
    POSIX_ENSURE(fingerprint, S2N_ERR_INVALID_ARGUMENT);
    fingerprint->client_hello = NULL;
    fingerprint->raw_size = 0;
    return S2N_SUCCESS;
}

int s2n_fingerprint_set_client_hello(struct s2n_fingerprint *fingerprint, struct s2n_client_hello *ch)
{
    POSIX_ENSURE(fingerprint, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(ch, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(!ch->sslv2, S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
    POSIX_GUARD(s2n_fingerprint_wipe(fingerprint));
    fingerprint->client_hello = ch;
    return S2N_SUCCESS;
}

int s2n_fingerprint_get_hash_size(const struct s2n_fingerprint *fingerprint, uint32_t *size)
{
    POSIX_ENSURE(fingerprint, S2N_ERR_INVALID_ARGUMENT);
    const struct s2n_fingerprint_method *method = fingerprint->method;
    POSIX_ENSURE_REF(method);
    POSIX_ENSURE(size, S2N_ERR_INVALID_ARGUMENT);
    *size = method->hash_str_size;
    return S2N_SUCCESS;
}

int s2n_fingerprint_get_hash(struct s2n_fingerprint *fingerprint,
        uint32_t max_output_size, uint8_t *output, uint32_t *output_size)
{
    POSIX_ENSURE(fingerprint, S2N_ERR_INVALID_ARGUMENT);
    const struct s2n_fingerprint_method *method = fingerprint->method;
    POSIX_ENSURE_REF(method);

    size_t min_output_size = method->hash_str_size;
    if (fingerprint->legacy_hash_format) {
        min_output_size /= 2;
    }

    POSIX_ENSURE(max_output_size >= min_output_size, S2N_ERR_INSUFFICIENT_MEM_SIZE);
    POSIX_ENSURE(output, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(output_size, S2N_ERR_INVALID_ARGUMENT);
    *output_size = 0;

    struct s2n_client_hello *client_hello = fingerprint->client_hello;
    POSIX_ENSURE(client_hello, S2N_ERR_INVALID_STATE);

    struct s2n_fingerprint_hash hash = {
        .hash = &fingerprint->hash,
        .legacy_hash_format = fingerprint->legacy_hash_format,
    };
    POSIX_GUARD(s2n_hash_reset(&fingerprint->hash));

    struct s2n_stuffer output_stuffer = { 0 };
    POSIX_GUARD(s2n_blob_init(&output_stuffer.blob, output, max_output_size));

    POSIX_GUARD_RESULT(method->fingerprint(client_hello, &hash, &output_stuffer));

    *output_size = s2n_stuffer_data_available(&output_stuffer);
    fingerprint->raw_size = hash.bytes_digested;
    return S2N_SUCCESS;
}

int s2n_fingerprint_get_raw_size(const struct s2n_fingerprint *fingerprint, uint32_t *size)
{
    POSIX_ENSURE(fingerprint, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(size, S2N_ERR_INVALID_ARGUMENT);
    /* A zero-length raw string is impossible for all fingerprinting methods
     * currently supported, so raw_size == 0 indicates that raw_size has not been
     * calculated yet.
     */
    POSIX_ENSURE(fingerprint->raw_size != 0, S2N_ERR_INVALID_STATE);
    *size = fingerprint->raw_size;
    return S2N_SUCCESS;
}

int s2n_fingerprint_get_raw(struct s2n_fingerprint *fingerprint,
        uint32_t max_output_size, uint8_t *output, uint32_t *output_size)
{
    POSIX_ENSURE(fingerprint, S2N_ERR_INVALID_ARGUMENT);
    const struct s2n_fingerprint_method *method = fingerprint->method;
    POSIX_ENSURE_REF(method);

    POSIX_ENSURE(max_output_size > 0, S2N_ERR_INSUFFICIENT_MEM_SIZE);
    POSIX_ENSURE(output, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(output_size, S2N_ERR_INVALID_ARGUMENT);
    *output_size = 0;

    struct s2n_client_hello *client_hello = fingerprint->client_hello;
    POSIX_ENSURE(client_hello, S2N_ERR_INVALID_STATE);

    struct s2n_stuffer output_stuffer = { 0 };
    POSIX_GUARD(s2n_blob_init(&output_stuffer.blob, output, max_output_size));
    struct s2n_fingerprint_hash hash = {
        .buffer = &output_stuffer,
    };

    POSIX_GUARD_RESULT(method->fingerprint(client_hello, &hash, &output_stuffer));

    *output_size = s2n_stuffer_data_available(&output_stuffer);
    fingerprint->raw_size = *output_size;
    return S2N_SUCCESS;
}

/* See https://datatracker.ietf.org/doc/html/rfc8701
 * for an explanation of GREASE and lists of the GREASE values.
 */
static S2N_RESULT s2n_assert_grease_value(uint16_t val)
{
    uint8_t byte1 = val >> 8;
    uint8_t byte2 = val & 0x00FF;
    /* Both bytes of the GREASE values are identical */
    RESULT_ENSURE_EQ(byte1, byte2);
    /* The GREASE value bytes all follow the format 0x[0-F]A.
     * So 0x0A, 0x1A, 0x2A etc, up to 0xFA. */
    RESULT_ENSURE_EQ((byte1 | 0xF0), 0xFA);
    return S2N_RESULT_OK;
}

bool s2n_is_grease_value(uint16_t val)
{
    return s2n_result_is_ok(s2n_assert_grease_value(val));
}

S2N_RESULT s2n_fingerprint_hash_add_char(struct s2n_fingerprint_hash *hash, char c)
{
    RESULT_ENSURE_REF(hash);
    if (hash->hash) {
        RESULT_GUARD_POSIX(s2n_hash_update(hash->hash, &c, 1));
    } else {
        RESULT_ENSURE_REF(hash->buffer);
        RESULT_ENSURE(s2n_stuffer_space_remaining(hash->buffer) >= 1,
                S2N_ERR_INSUFFICIENT_MEM_SIZE);
        RESULT_GUARD_POSIX(s2n_stuffer_write_char(hash->buffer, c));
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_hash_add_str(struct s2n_fingerprint_hash *hash,
        const char *str, size_t str_size)
{
    RESULT_ENSURE_REF(hash);
    RESULT_ENSURE(S2N_MEM_IS_READABLE(str, str_size), S2N_ERR_NULL);
    if (hash->hash) {
        RESULT_GUARD_POSIX(s2n_hash_update(hash->hash, str, str_size));
    } else {
        RESULT_ENSURE_REF(hash->buffer);
        RESULT_ENSURE(s2n_stuffer_space_remaining(hash->buffer) >= str_size,
                S2N_ERR_INSUFFICIENT_MEM_SIZE);
        RESULT_GUARD_POSIX(s2n_stuffer_write_text(hash->buffer, str, str_size));
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_hash_digest(struct s2n_fingerprint_hash *hash, uint8_t *out, size_t out_size)
{
    RESULT_ENSURE_REF(hash);
    RESULT_ENSURE_REF(hash->hash);

    uint64_t bytes = 0;
    RESULT_GUARD_POSIX(s2n_hash_get_currently_in_hash_total(hash->hash, &bytes));
    hash->bytes_digested += bytes;

    RESULT_GUARD_POSIX(s2n_hash_digest(hash->hash, out, out_size));
    RESULT_GUARD_POSIX(s2n_hash_reset(hash->hash));
    return S2N_RESULT_OK;
}

bool s2n_fingerprint_hash_do_digest(struct s2n_fingerprint_hash *hash)
{
    return hash && hash->hash;
}

int s2n_client_hello_get_fingerprint_hash(struct s2n_client_hello *ch, s2n_fingerprint_type type,
        uint32_t max_output_size, uint8_t *output, uint32_t *output_size, uint32_t *str_size)
{
    POSIX_ENSURE(type == S2N_FINGERPRINT_JA3, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(str_size, S2N_ERR_INVALID_ARGUMENT);
    DEFER_CLEANUP(struct s2n_fingerprint fingerprint = { .legacy_hash_format = true },
            s2n_fingerprint_free_fields);
    POSIX_GUARD_RESULT(s2n_fingerprint_init(&fingerprint, type));
    POSIX_GUARD(s2n_fingerprint_set_client_hello(&fingerprint, ch));
    POSIX_GUARD(s2n_fingerprint_get_hash(&fingerprint, max_output_size, output, output_size));
    POSIX_GUARD(s2n_fingerprint_get_raw_size(&fingerprint, str_size));
    return S2N_SUCCESS;
}

int s2n_client_hello_get_fingerprint_string(struct s2n_client_hello *ch, s2n_fingerprint_type type,
        uint32_t max_output_size, uint8_t *output, uint32_t *output_size)
{
    POSIX_ENSURE(type == S2N_FINGERPRINT_JA3, S2N_ERR_INVALID_ARGUMENT);
    DEFER_CLEANUP(struct s2n_fingerprint fingerprint = { 0 },
            s2n_fingerprint_free_fields);
    POSIX_GUARD_RESULT(s2n_fingerprint_init(&fingerprint, type));
    POSIX_GUARD(s2n_fingerprint_set_client_hello(&fingerprint, ch));
    POSIX_GUARD(s2n_fingerprint_get_raw(&fingerprint, max_output_size, output, output_size));
    return S2N_SUCCESS;
}
