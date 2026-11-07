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

#include <stdbool.h>

#include "utils/s2n_array.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"

/* An ECHConfig (RFC 9849, Section 4) with version 0xfe0d.
 *
 * The blobs are not owned: after s2n_ech_config_list_parse they point into the
 * parsed ECHConfigList, which must outlive the config.
 */
struct s2n_ech_config {
    /* The whole ECHConfig as it appears on the wire: version, length, and
     * contents. HPKE's info for ECH is built from these exact bytes. */
    struct s2n_blob raw;
    uint8_t config_id;
    uint16_t kem_id;
    struct s2n_blob public_key;
    /* The HpkeSymmetricCipherSuite list as it appears on the wire */
    struct s2n_blob cipher_suites;
    uint8_t maximum_name_length;
    struct s2n_blob public_name;
    /* The ECHConfigExtension list as it appears on the wire */
    struct s2n_blob extensions;
};

/* Parses an ECHConfigList and appends each ECHConfig with version 0xfe0d to
 * `configs`, an array of struct s2n_ech_config. ECHConfigs with any other
 * version are skipped.
 *
 * The parse checks structure only. It does not decide whether s2n-tls can use
 * a config's KEM, public key, cipher suites, or extensions: the caller does,
 * because a server loading its own configs and a client choosing one of a
 * server's need different policies.
 *
 * A malformed list fails with S2N_ERR_ECH_INVALID_CONFIG. On failure the
 * elements of `configs` are restored, but the array may have been
 * reallocated, so pointers to its elements taken before the call may no
 * longer be valid.
 */
S2N_RESULT s2n_ech_config_list_parse(const struct s2n_blob *list, struct s2n_array *configs);

/* Gets the number of HpkeSymmetricCipherSuites in a parsed config */
S2N_RESULT s2n_ech_config_get_cipher_suite_count(const struct s2n_ech_config *config, uint16_t *count);

/* Gets the HpkeSymmetricCipherSuite at position `suite_number` in a parsed config */
S2N_RESULT s2n_ech_config_get_cipher_suite(const struct s2n_ech_config *config, uint16_t suite_number,
        uint16_t *kdf_id, uint16_t *aead_id);

/* Checks whether a config has a mandatory extension, one whose type has the
 * high bit set (RFC 9849, Section 4.2) */
S2N_RESULT s2n_ech_config_has_mandatory_extension(const struct s2n_ech_config *config, bool *found);
