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

#include "tls/s2n_ech_config.h"

#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_ech_parse.h"
#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_bitmap.h"
#include "utils/s2n_safety.h"

/* version (2 bytes) and length (2 bytes) of an ECHConfig */
#define S2N_ECH_CONFIG_LIST_MIN_SIZE 4

/* kdf_id (2 bytes) and aead_id (2 bytes) */
#define S2N_ECH_CIPHER_SUITE_SIZE 4

/* An ECHConfigExtensionType with the high bit set is mandatory */
#define S2N_ECH_MANDATORY_EXTENSION_BIT 0x8000

/* One bit for each ECHConfigExtensionType */
#define S2N_ECH_EXTENSION_TYPES_SEEN_SIZE ((UINT16_MAX + 1) / 8)

/* Checks that `extensions` is a well-formed ECHConfigExtension list with no
 * repeated type, using `seen`, which must have no bits set. Clears the bits
 * it sets before returning successfully, so `seen` can be reused for the
 * next config without clearing all of it.
 *
 *= https://www.rfc-editor.org/rfc/rfc9849#section-4
 *#     struct {
 *#         ECHConfigExtensionType type;
 *#         opaque data<0..2^16-1>;
 *#     } ECHConfigExtension;
 *
 *= https://www.rfc-editor.org/rfc/rfc9849#section-4.2
 *# ECH configuration extensions follow the same interpretation rules as
 *# TLS extensions: extensions MAY appear in any order, but there MUST
 *# NOT be more than one extension of the same type in the extensions
 *# block.
 */
static S2N_RESULT s2n_ech_config_extensions_validate(const struct s2n_blob *extensions, uint8_t *seen)
{
    struct s2n_blob extensions_copy = *extensions;
    struct s2n_stuffer in = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&in, &extensions_copy));
    while (s2n_stuffer_data_available(&in)) {
        uint16_t type = 0;
        struct s2n_blob data = { 0 };
        RESULT_GUARD(s2n_ech_read_extension(&in, &type, &data, NULL, S2N_ERR_ECH_INVALID_CONFIG));
        RESULT_ENSURE(!S2N_CBIT_TEST(seen, type), S2N_ERR_ECH_INVALID_CONFIG);
        S2N_CBIT_SET(seen, type);
    }

    RESULT_GUARD_POSIX(s2n_stuffer_reread(&in));
    while (s2n_stuffer_data_available(&in)) {
        uint16_t type = 0;
        struct s2n_blob data = { 0 };
        RESULT_GUARD(s2n_ech_read_extension(&in, &type, &data, NULL, S2N_ERR_ECH_INVALID_CONFIG));
        S2N_CBIT_CLR(seen, type);
    }
    return S2N_RESULT_OK;
}

/*
 *= https://www.rfc-editor.org/rfc/rfc9849#section-4
 *#     struct {
 *#         HpkeKeyConfig key_config;
 *#         uint8 maximum_name_length;
 *#         opaque public_name<1..255>;
 *#         ECHConfigExtension extensions<0..2^16-1>;
 *#     } ECHConfigContents;
 */
static S2N_RESULT s2n_ech_config_contents_parse(struct s2n_blob *contents, uint8_t *seen,
        struct s2n_ech_config *config)
{
    struct s2n_stuffer in = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&in, contents));

    RESULT_GUARD(s2n_ech_read_uint8(&in, &config->config_id, S2N_ERR_ECH_INVALID_CONFIG));
    RESULT_GUARD(s2n_ech_read_uint16(&in, &config->kem_id, S2N_ERR_ECH_INVALID_CONFIG));

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-4
     *#     opaque HpkePublicKey<1..2^16-1>;
     */
    RESULT_GUARD(s2n_ech_read_uint16_vector(&in, &config->public_key, S2N_ERR_ECH_INVALID_CONFIG));
    RESULT_ENSURE(config->public_key.size >= 1, S2N_ERR_ECH_INVALID_CONFIG);

    /* A whole number of suites fits in at most 2^16-4 bytes, so only the
     * lower bound needs checking.
     *
     *= https://www.rfc-editor.org/rfc/rfc9849#section-4
     *#         HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
     */
    RESULT_GUARD(s2n_ech_read_uint16_vector(&in, &config->cipher_suites, S2N_ERR_ECH_INVALID_CONFIG));
    RESULT_ENSURE(config->cipher_suites.size >= S2N_ECH_CIPHER_SUITE_SIZE, S2N_ERR_ECH_INVALID_CONFIG);
    RESULT_ENSURE(config->cipher_suites.size % S2N_ECH_CIPHER_SUITE_SIZE == 0, S2N_ERR_ECH_INVALID_CONFIG);

    RESULT_GUARD(s2n_ech_read_uint8(&in, &config->maximum_name_length, S2N_ERR_ECH_INVALID_CONFIG));
    RESULT_GUARD(s2n_ech_read_uint8_vector(&in, &config->public_name, S2N_ERR_ECH_INVALID_CONFIG));
    RESULT_ENSURE(config->public_name.size >= 1, S2N_ERR_ECH_INVALID_CONFIG);

    RESULT_GUARD(s2n_ech_read_uint16_vector(&in, &config->extensions, S2N_ERR_ECH_INVALID_CONFIG));
    RESULT_GUARD(s2n_ech_config_extensions_validate(&config->extensions, seen));

    RESULT_ENSURE(s2n_stuffer_data_available(&in) == 0, S2N_ERR_ECH_INVALID_CONFIG);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_ech_config_list_parse_impl(const struct s2n_blob *list, struct s2n_array *configs)
{
    struct s2n_blob list_copy = *list;
    struct s2n_stuffer in = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&in, &list_copy));

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-4
     *#     ECHConfig ECHConfigList<4..2^16-1>;
     */
    struct s2n_blob configs_blob = { 0 };
    RESULT_GUARD(s2n_ech_read_uint16_vector(&in, &configs_blob, S2N_ERR_ECH_INVALID_CONFIG));
    RESULT_ENSURE(configs_blob.size >= S2N_ECH_CONFIG_LIST_MIN_SIZE, S2N_ERR_ECH_INVALID_CONFIG);
    RESULT_ENSURE(s2n_stuffer_data_available(&in) == 0, S2N_ERR_ECH_INVALID_CONFIG);

    uint8_t seen[S2N_ECH_EXTENSION_TYPES_SEEN_SIZE] = { 0 };

    struct s2n_stuffer configs_in = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&configs_in, &configs_blob));
    while (s2n_stuffer_data_available(&configs_in)) {
        uint32_t config_start = configs_in.read_cursor;
        uint16_t version = 0;
        RESULT_GUARD(s2n_ech_read_uint16(&configs_in, &version, S2N_ERR_ECH_INVALID_CONFIG));
        struct s2n_blob contents = { 0 };
        RESULT_GUARD(s2n_ech_read_uint16_vector(&configs_in, &contents, S2N_ERR_ECH_INVALID_CONFIG));

        /*
         *= https://www.rfc-editor.org/rfc/rfc9849#section-4
         *# The version is the same as the code point for the
         *# "encrypted_client_hello" extension.  Clients MUST ignore any
         *# ECHConfig structure with a version they do not support.
         */
        if (version != TLS_EXTENSION_ECH) {
            continue;
        }

        struct s2n_ech_config config = { 0 };
        RESULT_GUARD_POSIX(s2n_blob_slice(&configs_blob, &config.raw, config_start,
                configs_in.read_cursor - config_start));
        RESULT_GUARD(s2n_ech_config_contents_parse(&contents, seen, &config));

        struct s2n_ech_config *element = NULL;
        RESULT_GUARD(s2n_array_pushback(configs, (void **) &element));
        *element = config;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ech_config_list_parse(const struct s2n_blob *list, struct s2n_array *configs)
{
    RESULT_ENSURE_REF(list);
    RESULT_ENSURE_REF(configs);
    RESULT_ENSURE(configs->element_size == sizeof(struct s2n_ech_config), S2N_ERR_SAFETY);

    uint32_t initial_count = 0;
    RESULT_GUARD(s2n_array_num_elements(configs, &initial_count));

    s2n_result result = s2n_ech_config_list_parse_impl(list, configs);
    if (s2n_result_is_error(result)) {
        /* Remove any configs parsed before the error */
        uint32_t count = 0;
        RESULT_GUARD(s2n_array_num_elements(configs, &count));
        while (count > initial_count) {
            count--;
            RESULT_GUARD(s2n_array_remove(configs, count));
        }
    }
    return result;
}

S2N_RESULT s2n_ech_config_get_cipher_suite_count(const struct s2n_ech_config *config, uint16_t *count)
{
    RESULT_ENSURE_REF(config);
    RESULT_ENSURE_REF(count);
    *count = config->cipher_suites.size / S2N_ECH_CIPHER_SUITE_SIZE;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ech_config_get_cipher_suite(const struct s2n_ech_config *config, uint16_t suite_number,
        uint16_t *kdf_id, uint16_t *aead_id)
{
    RESULT_ENSURE_REF(kdf_id);
    RESULT_ENSURE_REF(aead_id);
    uint16_t count = 0;
    RESULT_GUARD(s2n_ech_config_get_cipher_suite_count(config, &count));
    RESULT_ENSURE(suite_number < count, S2N_ERR_INVALID_ARGUMENT);

    struct s2n_blob suite = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_slice(&config->cipher_suites, &suite, suite_number * S2N_ECH_CIPHER_SUITE_SIZE,
            S2N_ECH_CIPHER_SUITE_SIZE));
    struct s2n_stuffer in = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&in, &suite));
    RESULT_GUARD(s2n_ech_read_uint16(&in, kdf_id, S2N_ERR_ECH_INVALID_CONFIG));
    RESULT_GUARD(s2n_ech_read_uint16(&in, aead_id, S2N_ERR_ECH_INVALID_CONFIG));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ech_config_has_mandatory_extension(const struct s2n_ech_config *config, bool *found)
{
    RESULT_ENSURE_REF(config);
    RESULT_ENSURE_REF(found);
    *found = false;

    struct s2n_blob extensions = config->extensions;
    struct s2n_stuffer in = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&in, &extensions));
    while (s2n_stuffer_data_available(&in)) {
        uint16_t type = 0;
        struct s2n_blob data = { 0 };
        RESULT_GUARD(s2n_ech_read_extension(&in, &type, &data, NULL, S2N_ERR_ECH_INVALID_CONFIG));
        if (type & S2N_ECH_MANDATORY_EXTENSION_BIT) {
            *found = true;
        }
    }
    return S2N_RESULT_OK;
}
