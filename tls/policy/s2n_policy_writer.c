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

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "stuffer/s2n_stuffer.h"
#include "tls/policy/s2n_policy_feature.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_security_rules.h"
#include "utils/s2n_safety.h"

#define BOOL_STR(b) ((b) ? "yes" : "no")

extern const struct s2n_security_rule security_rule_definitions[S2N_SECURITY_RULES_COUNT];
extern struct s2n_security_policy_selection security_policy_selection[];

static const char *version_strs[] = {
    [S2N_SSLv2] = "SSLv2",
    [S2N_SSLv3] = "SSLv3",
    [S2N_TLS10] = "TLS1.0",
    [S2N_TLS11] = "TLS1.1",
    [S2N_TLS12] = "TLS1.2",
    [S2N_TLS13] = "TLS1.3",
};

static S2N_RESULT s2n_security_policy_write_format_v1_to_stuffer(const struct s2n_security_policy *policy, struct s2n_stuffer *stuffer)
{
    RESULT_ENSURE_REF(policy);
    RESULT_ENSURE_REF(stuffer);

    const char *version_str = NULL;
    if (policy->minimum_protocol_version <= S2N_TLS13) {
        version_str = version_strs[policy->minimum_protocol_version];
    }
    RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "min version: %s\n", version_str ? version_str : "None"));

    RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "rules:\n"));
    for (size_t i = 0; i < S2N_SECURITY_RULES_COUNT; i++) {
        RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "- %s: %s\n",
                security_rule_definitions[i].name, BOOL_STR(policy->rules[i])));
    }

    RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "cipher suites:\n"));
    if (policy->cipher_preferences->allow_chacha20_boosting) {
        RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "- chacha20 boosting enabled\n"));
    }
    for (size_t i = 0; i < policy->cipher_preferences->count; i++) {
        RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "- %s\n", policy->cipher_preferences->suites[i]->iana_name));
    }

    RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "signature schemes:\n"));
    for (size_t i = 0; i < policy->signature_preferences->count; i++) {
        RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "- %s\n", policy->signature_preferences->signature_schemes[i]->name));
    }

    RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "curves:\n"));
    for (size_t i = 0; i < policy->ecc_preferences->count; i++) {
        RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "- %s\n", policy->ecc_preferences->ecc_curves[i]->name));
    }

    if (policy->certificate_signature_preferences) {
        if (policy->certificate_preferences_apply_locally) {
            RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "certificate preferences apply locally\n"));
        }
        RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "certificate signature schemes:\n"));
        for (size_t i = 0; i < policy->certificate_signature_preferences->count; i++) {
            RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "- %s\n",
                    policy->certificate_signature_preferences->signature_schemes[i]->name));
        }
    }

    if (policy->certificate_key_preferences) {
        RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "certificate keys:\n"));
        for (size_t i = 0; i < policy->certificate_key_preferences->count; i++) {
            RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "- %s\n",
                    policy->certificate_key_preferences->certificate_keys[i]->name));
        }
    }

    if (policy->kem_preferences && policy->kem_preferences != &kem_preferences_null) {
        RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "pq:\n"));
        RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "- revision: %i\n",
                policy->kem_preferences->tls13_pq_hybrid_draft_revision));

        if (policy->kem_preferences->kem_count > 0) {
            RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "- kems:\n"));
            for (size_t i = 0; i < policy->kem_preferences->kem_count; i++) {
                RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "-- %s\n",
                        policy->kem_preferences->kems[i]->name));
            }
        }

        RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "- kem groups:\n"));
        for (size_t i = 0; i < policy->kem_preferences->tls13_kem_group_count; i++) {
            RESULT_GUARD_POSIX(s2n_stuffer_printf(stuffer, "-- %s\n",
                    policy->kem_preferences->tls13_kem_groups[i]->name));
        }
    }

    return S2N_RESULT_OK;
}

int s2n_security_policy_write_buffer(const struct s2n_security_policy *policy,
        s2n_policy_format format, uint8_t *buffer, uint32_t buffer_length)
{
    POSIX_ENSURE_REF(policy);
    POSIX_ENSURE_REF(buffer);

    /* Calculate the required size by writing to a temporary stuffer, then verify the provided buffer is large enough */
    DEFER_CLEANUP(struct s2n_stuffer temp_stuffer = { 0 }, s2n_stuffer_free);
    POSIX_GUARD(s2n_stuffer_growable_alloc(&temp_stuffer, 1024));

    switch (format) {
        case S2N_POLICY_FORMAT_DEBUG_V1:
            POSIX_GUARD_RESULT(s2n_security_policy_write_format_v1_to_stuffer(policy, &temp_stuffer));
            break;
        default:
            POSIX_BAIL(S2N_ERR_INVALID_ARGUMENT);
    }

    uint32_t required_size = s2n_stuffer_data_available(&temp_stuffer);
    POSIX_ENSURE(buffer_length >= required_size, S2N_ERR_INSUFFICIENT_MEM_SIZE);

    /* Copy the data from temp stuffer to user buffer */
    POSIX_CHECKED_MEMCPY(buffer, temp_stuffer.blob.data, required_size);

    return S2N_SUCCESS;
}

int s2n_security_policy_write_fd(const struct s2n_security_policy *policy,
        s2n_policy_format format, int fd)
{
    POSIX_ENSURE_REF(policy);
    POSIX_ENSURE(fd >= 0, S2N_ERR_INVALID_ARGUMENT);

    DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
    POSIX_GUARD(s2n_stuffer_growable_alloc(&stuffer, 1024));

    switch (format) {
        case S2N_POLICY_FORMAT_DEBUG_V1:
            POSIX_GUARD_RESULT(s2n_security_policy_write_format_v1_to_stuffer(policy, &stuffer));
            break;
        default:
            POSIX_BAIL(S2N_ERR_INVALID_ARGUMENT);
    }

    /* Write the buffer to the file descriptor */
    uint32_t data_size = s2n_stuffer_data_available(&stuffer);
    ssize_t written = write(fd, stuffer.blob.data, data_size);
    POSIX_ENSURE(written == (ssize_t) data_size, S2N_ERR_IO);

    return S2N_SUCCESS;
}
