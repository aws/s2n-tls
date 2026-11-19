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

/* Target Functions: s2n_ech_config_list_parse s2n_ech_config_get_cipher_suite
 *                   s2n_ech_config_has_mandatory_extension */

#include <stdint.h>

#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_ech_config.h"
#include "utils/s2n_array.h"
#include "utils/s2n_safety.h"

static bool s2n_blobs_equal(const struct s2n_blob *a, const struct s2n_blob *b)
{
    return a->size == b->size && s2n_constant_time_equals(a->data, b->data, a->size);
}

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
    S2N_FUZZ_ENSURE_MIN_LEN(len, 1);

    /* Copy the input so that the parsed configs point into s2n-owned memory */
    DEFER_CLEANUP(struct s2n_blob input = { 0 }, s2n_free);
    POSIX_GUARD(s2n_alloc(&input, len));
    POSIX_CHECKED_MEMCPY(input.data, buf, len);

    DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)), s2n_array_free_p);
    POSIX_ENSURE_REF(configs);

    if (s2n_result_is_error(s2n_ech_config_list_parse(&input, configs))) {
        return S2N_SUCCESS;
    }

    uint32_t count = 0;
    POSIX_GUARD_RESULT(s2n_array_num_elements(configs, &count));
    for (uint32_t i = 0; i < count; i++) {
        struct s2n_ech_config *config = NULL;
        POSIX_GUARD_RESULT(s2n_array_get(configs, i, (void **) &config));

        /* Every cipher suite of a parsed config can be read */
        uint16_t suite_count = 0;
        POSIX_GUARD_RESULT(s2n_ech_config_get_cipher_suite_count(config, &suite_count));
        for (uint16_t j = 0; j < suite_count; j++) {
            uint16_t kdf_id = 0;
            uint16_t aead_id = 0;
            POSIX_GUARD_RESULT(s2n_ech_config_get_cipher_suite(config, j, &kdf_id, &aead_id));
        }
        bool mandatory = false;
        POSIX_GUARD_RESULT(s2n_ech_config_has_mandatory_extension(config, &mandatory));

        /* A config's raw bytes, alone in a list, parse to the same config */
        DEFER_CLEANUP(struct s2n_stuffer single = { 0 }, s2n_stuffer_free);
        POSIX_GUARD(s2n_stuffer_growable_alloc(&single, 0));
        POSIX_GUARD(s2n_stuffer_write_uint16(&single, config->raw.size));
        POSIX_GUARD(s2n_stuffer_write(&single, &config->raw));
        struct s2n_blob single_blob = { 0 };
        POSIX_GUARD(s2n_blob_init(&single_blob, single.blob.data, s2n_stuffer_data_available(&single)));

        DEFER_CLEANUP(struct s2n_array *reparsed = s2n_array_new(sizeof(struct s2n_ech_config)), s2n_array_free_p);
        POSIX_ENSURE_REF(reparsed);
        POSIX_GUARD_RESULT(s2n_ech_config_list_parse(&single_blob, reparsed));
        uint32_t reparsed_count = 0;
        POSIX_GUARD_RESULT(s2n_array_num_elements(reparsed, &reparsed_count));
        POSIX_ENSURE_EQ(reparsed_count, 1);

        struct s2n_ech_config *copy = NULL;
        POSIX_GUARD_RESULT(s2n_array_get(reparsed, 0, (void **) &copy));
        POSIX_ENSURE(s2n_blobs_equal(&copy->raw, &config->raw), S2N_ERR_SAFETY);
        POSIX_ENSURE_EQ(copy->config_id, config->config_id);
        POSIX_ENSURE_EQ(copy->kem_id, config->kem_id);
        POSIX_ENSURE(s2n_blobs_equal(&copy->public_key, &config->public_key), S2N_ERR_SAFETY);
        POSIX_ENSURE(s2n_blobs_equal(&copy->cipher_suites, &config->cipher_suites), S2N_ERR_SAFETY);
        POSIX_ENSURE_EQ(copy->maximum_name_length, config->maximum_name_length);
        POSIX_ENSURE(s2n_blobs_equal(&copy->public_name, &config->public_name), S2N_ERR_SAFETY);
        POSIX_ENSURE(s2n_blobs_equal(&copy->extensions, &config->extensions), S2N_ERR_SAFETY);
    }

    return S2N_SUCCESS;
}

S2N_FUZZ_TARGET(NULL, s2n_fuzz_test, NULL)
