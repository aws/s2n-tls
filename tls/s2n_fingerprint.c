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

#include "api/unstable/fingerprint.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_hash.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/extensions/s2n_extension_list.h"
#include "tls/s2n_client_hello.h"
#include "tls/s2n_crypto_constants.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

#define S2N_JA3_FIELD_DIV ','
#define S2N_JA3_LIST_DIV  '-'

/* UINT16_MAX == 65535 */
#define S2N_UINT16_STR_MAX_SIZE 5

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

static bool s2n_is_grease_value(uint16_t val)
{
    return s2n_result_is_ok(s2n_assert_grease_value(val));
}

static S2N_RESULT s2n_fingerprint_hash_flush(struct s2n_hash_state *hash, struct s2n_stuffer *in)
{
    if (hash == NULL) {
        /* If the buffer is full and needs to be flushed, but no hash was provided,
         * then we have insufficient memory to complete the fingerprint.
         *
         * The application will need to provide a larger buffer.
         */
        RESULT_BAIL(S2N_ERR_INSUFFICIENT_MEM_SIZE);
    }

    uint32_t hash_data_len = s2n_stuffer_data_available(in);
    uint8_t *hash_data = s2n_stuffer_raw_read(in, hash_data_len);
    RESULT_ENSURE_REF(hash_data);
    RESULT_GUARD_POSIX(s2n_hash_update(hash, hash_data, hash_data_len));
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(in));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_write_char(struct s2n_stuffer *stuffer,
        char c, struct s2n_hash_state *hash)
{
    if (s2n_stuffer_space_remaining(stuffer) < 1) {
        RESULT_GUARD(s2n_fingerprint_hash_flush(hash, stuffer));
    }
    RESULT_GUARD_POSIX(s2n_stuffer_write_char(stuffer, c));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_write_entry(struct s2n_stuffer *stuffer,
        bool *is_list, uint16_t value, struct s2n_hash_state *hash)
{
    /* If we have already written at least one value for this field,
     * then we are writing a list and need to prepend a list divider before
     * writing the next value.
     */
    RESULT_ENSURE_REF(is_list);
    if (*is_list) {
        RESULT_GUARD(s2n_fingerprint_write_char(stuffer, S2N_JA3_LIST_DIV, hash));
    }
    *is_list = true;

    /* snprintf always appends a '\0' to the output,
     * but that extra '\0' is not included in the return value */
    uint8_t entry[S2N_UINT16_STR_MAX_SIZE + 1] = { 0 };
    int written = snprintf((char *) entry, sizeof(entry), "%u", value);
    RESULT_ENSURE_GT(written, 0);
    RESULT_ENSURE_LTE(written, S2N_UINT16_STR_MAX_SIZE);

    if (s2n_stuffer_space_remaining(stuffer) < (uint64_t) written) {
        RESULT_GUARD(s2n_fingerprint_hash_flush(hash, stuffer));
    }
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(stuffer, entry, written));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_write_version(struct s2n_client_hello *ch,
        struct s2n_stuffer *output, struct s2n_hash_state *hash)
{
    RESULT_ENSURE_REF(ch);
    bool is_list = false;
    uint16_t version = 0;
    struct s2n_stuffer message = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&message, &ch->raw_message));
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&message, &version));
    RESULT_GUARD(s2n_fingerprint_write_entry(output, &is_list, version, hash));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_write_ciphers(struct s2n_client_hello *ch,
        struct s2n_stuffer *output, struct s2n_hash_state *hash)
{
    RESULT_ENSURE_REF(ch);

    bool cipher_found = false;
    struct s2n_stuffer ciphers = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&ciphers, &ch->cipher_suites));
    while (s2n_stuffer_data_available(&ciphers)) {
        uint16_t cipher = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&ciphers, &cipher));
        if (s2n_is_grease_value(cipher)) {
            continue;
        }
        RESULT_GUARD(s2n_fingerprint_write_entry(output, &cipher_found, cipher, hash));
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_write_extensions(struct s2n_client_hello *ch,
        struct s2n_stuffer *output, struct s2n_hash_state *hash)
{
    RESULT_ENSURE_REF(ch);

    /* We have to use the raw extensions instead of the parsed extensions
     * because s2n-tls both intentionally ignores any unknown extensions
     * and reorders the extensions when parsing the list.
     */
    struct s2n_stuffer extensions = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&extensions, &ch->extensions.raw));

    bool extension_found = false;
    while (s2n_stuffer_data_available(&extensions)) {
        uint16_t extension = 0, extension_size = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&extensions, &extension));
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&extensions, &extension_size));
        RESULT_GUARD_POSIX(s2n_stuffer_skip_read(&extensions, extension_size));
        if (s2n_is_grease_value(extension)) {
            continue;
        }
        RESULT_GUARD(s2n_fingerprint_write_entry(output, &extension_found, extension, hash));
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_write_elliptic_curves(struct s2n_client_hello *ch,
        struct s2n_stuffer *output, struct s2n_hash_state *hash)
{
    RESULT_ENSURE_REF(ch);

    s2n_parsed_extension *elliptic_curves_extension = NULL;
    int result = s2n_client_hello_get_parsed_extension(S2N_EXTENSION_SUPPORTED_GROUPS,
            &ch->extensions, &elliptic_curves_extension);
    if (result != S2N_SUCCESS) {
        return S2N_RESULT_OK;
    }

    struct s2n_stuffer elliptic_curves = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&elliptic_curves,
            &elliptic_curves_extension->extension));

    uint16_t count = 0;
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&elliptic_curves, &count));

    bool curve_found = false;
    while (s2n_stuffer_data_available(&elliptic_curves)) {
        uint16_t curve = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&elliptic_curves, &curve));
        if (s2n_is_grease_value(curve)) {
            continue;
        }
        RESULT_GUARD(s2n_fingerprint_write_entry(output, &curve_found, curve, hash));
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_write_point_formats(struct s2n_client_hello *ch,
        struct s2n_stuffer *output, struct s2n_hash_state *hash)
{
    RESULT_ENSURE_REF(ch);

    s2n_parsed_extension *point_formats_extension = NULL;
    int result = s2n_client_hello_get_parsed_extension(S2N_EXTENSION_EC_POINT_FORMATS,
            &ch->extensions, &point_formats_extension);
    if (result != S2N_SUCCESS) {
        return S2N_RESULT_OK;
    }

    struct s2n_stuffer point_formats = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&point_formats,
            &point_formats_extension->extension));

    uint8_t count = 0;
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint8(&point_formats, &count));

    bool format_found = false;
    while (s2n_stuffer_data_available(&point_formats)) {
        uint8_t format = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint8(&point_formats, &format));
        RESULT_GUARD(s2n_fingerprint_write_entry(output, &format_found, format, hash));
    }
    return S2N_RESULT_OK;
}

/* JA3 involves concatenating a set of fields from the ClientHello:
 *      SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
 * For example:
 *      "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
 * See https://github.com/salesforce/ja3
 */
static S2N_RESULT s2n_fingerprint_ja3(struct s2n_client_hello *ch,
        struct s2n_stuffer *output, uint32_t *output_size, struct s2n_hash_state *hash)
{
    RESULT_ENSURE_REF(ch);
    RESULT_ENSURE(!ch->sslv2, S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

    RESULT_GUARD(s2n_fingerprint_write_version(ch, output, hash));
    RESULT_GUARD(s2n_fingerprint_write_char(output, S2N_JA3_FIELD_DIV, hash));
    RESULT_GUARD(s2n_fingerprint_write_ciphers(ch, output, hash));
    RESULT_GUARD(s2n_fingerprint_write_char(output, S2N_JA3_FIELD_DIV, hash));
    RESULT_GUARD(s2n_fingerprint_write_extensions(ch, output, hash));
    RESULT_GUARD(s2n_fingerprint_write_char(output, S2N_JA3_FIELD_DIV, hash));
    RESULT_GUARD(s2n_fingerprint_write_elliptic_curves(ch, output, hash));
    RESULT_GUARD(s2n_fingerprint_write_char(output, S2N_JA3_FIELD_DIV, hash));
    RESULT_GUARD(s2n_fingerprint_write_point_formats(ch, output, hash));

    return S2N_RESULT_OK;
}

int s2n_client_hello_get_fingerprint_hash(struct s2n_client_hello *ch, s2n_fingerprint_type type,
        uint32_t max_hash_size, uint8_t *hash, uint32_t *hash_size, uint32_t *str_size)
{
    POSIX_ENSURE(type == S2N_FINGERPRINT_JA3, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(max_hash_size >= MD5_DIGEST_LENGTH, S2N_ERR_INSUFFICIENT_MEM_SIZE);
    POSIX_ENSURE_REF(hash);
    POSIX_ENSURE_REF(hash_size);
    POSIX_ENSURE_REF(str_size);
    *hash_size = 0;
    *str_size = 0;

    /* The maximum size of the JA3 string is variable and could theoretically
     * be extremely large. However, we don't need enough memory to hold the full
     * string when calculating a hash. We can calculate and add the JA3 string
     * to the hash in chunks, similarly to how the TLS transcript hash is
     * calculated by adding handshake messages to the hash as they become
     * available. After a chunk is added to the hash, the string buffer can be
     * wiped and reused for the next chunk.
     *
     * The size of this buffer was chosen fairly arbitrarily.
     */
    uint8_t string_mem[50] = { 0 };
    struct s2n_blob string_blob = { 0 };
    struct s2n_stuffer string_stuffer = { 0 };
    POSIX_GUARD(s2n_blob_init(&string_blob, string_mem, sizeof(string_mem)));
    POSIX_GUARD(s2n_stuffer_init(&string_stuffer, &string_blob));

    /* JA3 uses an MD5 hash.
     * The hash doesn't have to be cryptographically secure,
     * so the weakness of MD5 shouldn't be a problem.
     */
    DEFER_CLEANUP(struct s2n_hash_state md5_hash = { 0 }, s2n_hash_free);
    POSIX_GUARD(s2n_hash_new(&md5_hash));
    if (s2n_is_in_fips_mode()) {
        /* This hash is unrelated to TLS and does not affect FIPS */
        POSIX_GUARD(s2n_hash_allow_md5_for_fips(&md5_hash));
    }
    POSIX_GUARD(s2n_hash_init(&md5_hash, S2N_HASH_MD5));

    POSIX_GUARD_RESULT(s2n_fingerprint_ja3(ch, &string_stuffer, hash_size, &md5_hash));
    POSIX_GUARD_RESULT(s2n_fingerprint_hash_flush(&md5_hash, &string_stuffer));

    uint64_t in_hash = 0;
    POSIX_GUARD(s2n_hash_get_currently_in_hash_total(&md5_hash, &in_hash));
    POSIX_ENSURE_LTE(in_hash, UINT32_MAX);
    *str_size = in_hash;

    POSIX_GUARD(s2n_hash_digest(&md5_hash, hash, MD5_DIGEST_LENGTH));
    *hash_size = MD5_DIGEST_LENGTH;
    return S2N_SUCCESS;
}

int s2n_client_hello_get_fingerprint_string(struct s2n_client_hello *ch, s2n_fingerprint_type type,
        uint32_t max_size, uint8_t *output, uint32_t *output_size)
{
    POSIX_ENSURE(type == S2N_FINGERPRINT_JA3, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(max_size > 0, S2N_ERR_INSUFFICIENT_MEM_SIZE);
    POSIX_ENSURE_REF(output);
    POSIX_ENSURE_REF(output_size);
    *output_size = 0;

    struct s2n_blob output_blob = { 0 };
    struct s2n_stuffer output_stuffer = { 0 };
    POSIX_GUARD(s2n_blob_init(&output_blob, output, max_size));
    POSIX_GUARD(s2n_stuffer_init(&output_stuffer, &output_blob));

    POSIX_GUARD_RESULT(s2n_fingerprint_ja3(ch, &output_stuffer, output_size, NULL));
    *output_size = s2n_stuffer_data_available(&output_stuffer);

    return S2N_SUCCESS;
}
