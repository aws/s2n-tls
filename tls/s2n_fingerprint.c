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

static S2N_RESULT s2n_fingerprint_hash_flush(struct s2n_fingerprint_hash *hash)
{
    RESULT_ENSURE_REF(hash);

    uint32_t hash_data_len = s2n_stuffer_data_available(hash->buffer);
    uint8_t *hash_data = s2n_stuffer_raw_read(hash->buffer, hash_data_len);
    RESULT_ENSURE_REF(hash_data);

    RESULT_GUARD_POSIX(s2n_hash_update(hash->hash, hash_data, hash_data_len));
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(hash->buffer));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_hash_reserve_space(struct s2n_fingerprint_hash *hash, size_t size)
{
    RESULT_ENSURE_REF(hash);
    if (s2n_stuffer_space_remaining(hash->buffer) < size) {
        RESULT_ENSURE(hash->hash, S2N_ERR_INSUFFICIENT_MEM_SIZE);
        RESULT_GUARD(s2n_fingerprint_hash_flush(hash));
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_hash_add_char(struct s2n_fingerprint_hash *hash, char c)
{
    RESULT_GUARD(s2n_fingerprint_hash_reserve_space(hash, 1));
    RESULT_GUARD_POSIX(s2n_stuffer_write_char(hash->buffer, c));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_hash_add_str(struct s2n_fingerprint_hash *hash, const char *str)
{
    RESULT_GUARD(s2n_fingerprint_hash_reserve_space(hash, strlen(str)));
    RESULT_GUARD_POSIX(s2n_stuffer_write_str(hash->buffer, str));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_hash_digest(struct s2n_fingerprint_hash *hash, uint8_t *out, size_t out_size)
{
    RESULT_GUARD(s2n_fingerprint_hash_flush(hash));

    RESULT_ENSURE_REF(hash);
    RESULT_ENSURE_REF(hash->hash);
    hash->bytes_digested += hash->hash->currently_in_hash;

    RESULT_GUARD_POSIX(s2n_hash_digest(hash->hash, out, out_size));
    RESULT_GUARD_POSIX(s2n_hash_reset(hash->hash));
    return S2N_RESULT_OK;
}

int s2n_client_hello_get_fingerprint_hash(struct s2n_client_hello *ch, s2n_fingerprint_type type,
        uint32_t max_output_size, uint8_t *output, uint32_t *output_size, uint32_t *str_size)
{
    POSIX_ENSURE(type == S2N_FINGERPRINT_JA3, S2N_ERR_INVALID_ARGUMENT);
    const struct s2n_fingerprint_method *method = &ja3_fingerprint;

    uint8_t hash_size = 0;
    POSIX_GUARD(s2n_hash_digest_size(method->hash, &hash_size));
    POSIX_ENSURE(max_output_size >= hash_size, S2N_ERR_INSUFFICIENT_MEM_SIZE);

    POSIX_ENSURE_REF(ch);
    POSIX_ENSURE(!ch->sslv2, S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
    POSIX_ENSURE_REF(output);
    POSIX_ENSURE_REF(output_size);
    POSIX_ENSURE_REF(str_size);
    *output_size = 0;
    *str_size = 0;

    struct s2n_stuffer output_stuffer = { 0 };
    POSIX_GUARD(s2n_blob_init(&output_stuffer.blob, output, max_output_size));

    /* The maximum size of the hash input string is variable and could theoretically
     * be extremely large. However, we don't need enough memory to hold the full string
     * when calculating a hash. We can calculate and add the string to the hash in chunks,
     * similarly to how the TLS transcript hash is calculated by adding handshake
     * messages to the hash as they become available. After a chunk is added to the hash,
     * the buffer can be wiped and reused for the next chunk.
     *
     * This ensures that our calculation requires a constant amount of memory.
     *
     * The size of the buffer is chosen to be the block size of most hashes.
     */
    uint8_t hash_mem[64] = { 0 };
    struct s2n_stuffer hash_stuffer = { 0 };
    POSIX_GUARD(s2n_blob_init(&hash_stuffer.blob, hash_mem, sizeof(hash_mem)));

    DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
    POSIX_GUARD(s2n_hash_new(&hash_state));
    s2n_hash_allow_md5_for_fips(&hash_state);
    POSIX_GUARD(s2n_hash_init(&hash_state, method->hash));

    struct s2n_fingerprint_hash hash = {
        .buffer = &hash_stuffer,
        .hash = &hash_state,
        .do_digest = true,
    };

    POSIX_GUARD_RESULT(method->fingerprint(ch, &hash, &output_stuffer));
    *output_size = s2n_stuffer_data_available(&output_stuffer);
    *str_size = hash.bytes_digested;
    return S2N_SUCCESS;
}

int s2n_client_hello_get_fingerprint_string(struct s2n_client_hello *ch, s2n_fingerprint_type type,
        uint32_t max_output_size, uint8_t *output, uint32_t *output_size)
{
    POSIX_ENSURE(type == S2N_FINGERPRINT_JA3, S2N_ERR_INVALID_ARGUMENT);
    const struct s2n_fingerprint_method *method = &ja3_fingerprint;
    POSIX_ENSURE(max_output_size > 0, S2N_ERR_INSUFFICIENT_MEM_SIZE);

    POSIX_ENSURE_REF(ch);
    POSIX_ENSURE(!ch->sslv2, S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
    POSIX_ENSURE_REF(output);
    POSIX_ENSURE_REF(output_size);
    *output_size = 0;

    struct s2n_stuffer output_stuffer = { 0 };
    POSIX_GUARD(s2n_blob_init(&output_stuffer.blob, output, max_output_size));

    struct s2n_fingerprint_hash hash = {
        .buffer = &output_stuffer,
    };

    POSIX_GUARD_RESULT(method->fingerprint(ch, &hash, &output_stuffer));
    *output_size = s2n_stuffer_data_available(&output_stuffer);
    return S2N_SUCCESS;
}
