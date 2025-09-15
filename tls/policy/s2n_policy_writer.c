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

static S2N_RESULT s2n_write_fd_formatted(int fd, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    /* Calculate required buffer size */
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(NULL, 0, format, args_copy);
    va_end(args_copy);

    if (len < 0) {
        va_end(args);
        RESULT_BAIL(S2N_ERR_INVALID_ARGUMENT);
    }

    /* Allocate buffer and format string */
    DEFER_CLEANUP(struct s2n_blob buffer = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&buffer, len + 1));
    int result = vsnprintf((char *) buffer.data, buffer.size, format, args);
    va_end(args);

    if (result < 0 || result >= (int) buffer.size) {
        RESULT_BAIL(S2N_ERR_INVALID_ARGUMENT);
    }

    /* Write to file descriptor */
    ssize_t written = write(fd, buffer.data, len);
    if (written != len) {
        RESULT_BAIL(S2N_ERR_IO);
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_security_policy_write_format_v1(const struct s2n_security_policy *policy, int fd)
{
    RESULT_ENSURE_REF(policy);

    const char *version_str = NULL;
    if (policy->minimum_protocol_version <= S2N_TLS13) {
        version_str = version_strs[policy->minimum_protocol_version];
    }
    RESULT_GUARD(s2n_write_fd_formatted(fd, "min version: %s\n", version_str ? version_str : "None"));

    RESULT_GUARD(s2n_write_fd_formatted(fd, "rules:\n"));
    for (size_t i = 0; i < S2N_SECURITY_RULES_COUNT; i++) {
        RESULT_GUARD(s2n_write_fd_formatted(fd, "- %s: %s\n",
                security_rule_definitions[i].name, BOOL_STR(policy->rules[i])));
    }

    RESULT_GUARD(s2n_write_fd_formatted(fd, "cipher suites:\n"));
    if (policy->cipher_preferences->allow_chacha20_boosting) {
        RESULT_GUARD(s2n_write_fd_formatted(fd, "- chacha20 boosting enabled\n"));
    }
    for (size_t i = 0; i < policy->cipher_preferences->count; i++) {
        RESULT_GUARD(s2n_write_fd_formatted(fd, "- %s\n", policy->cipher_preferences->suites[i]->iana_name));
    }

    RESULT_GUARD(s2n_write_fd_formatted(fd, "signature schemes:\n"));
    for (size_t i = 0; i < policy->signature_preferences->count; i++) {
        RESULT_GUARD(s2n_write_fd_formatted(fd, "- %s\n", policy->signature_preferences->signature_schemes[i]->name));
    }

    RESULT_GUARD(s2n_write_fd_formatted(fd, "curves:\n"));
    for (size_t i = 0; i < policy->ecc_preferences->count; i++) {
        RESULT_GUARD(s2n_write_fd_formatted(fd, "- %s\n", policy->ecc_preferences->ecc_curves[i]->name));
    }

    if (policy->certificate_signature_preferences) {
        if (policy->certificate_preferences_apply_locally) {
            RESULT_GUARD(s2n_write_fd_formatted(fd, "certificate preferences apply locally\n"));
        }
        RESULT_GUARD(s2n_write_fd_formatted(fd, "certificate signature schemes:\n"));
        for (size_t i = 0; i < policy->certificate_signature_preferences->count; i++) {
            RESULT_GUARD(s2n_write_fd_formatted(fd, "- %s\n",
                    policy->certificate_signature_preferences->signature_schemes[i]->name));
        }
    }

    if (policy->certificate_key_preferences) {
        RESULT_GUARD(s2n_write_fd_formatted(fd, "certificate keys:\n"));
        for (size_t i = 0; i < policy->certificate_key_preferences->count; i++) {
            RESULT_GUARD(s2n_write_fd_formatted(fd, "- %s\n",
                    policy->certificate_key_preferences->certificate_keys[i]->name));
        }
    }

    if (policy->kem_preferences && policy->kem_preferences != &kem_preferences_null) {
        RESULT_GUARD(s2n_write_fd_formatted(fd, "pq:\n"));
        RESULT_GUARD(s2n_write_fd_formatted(fd, "- revision: %i\n",
                policy->kem_preferences->tls13_pq_hybrid_draft_revision));

        if (policy->kem_preferences->kem_count > 0) {
            RESULT_GUARD(s2n_write_fd_formatted(fd, "- kems:\n"));
            for (size_t i = 0; i < policy->kem_preferences->kem_count; i++) {
                RESULT_GUARD(s2n_write_fd_formatted(fd, "-- %s\n",
                        policy->kem_preferences->kems[i]->name));
            }
        }

        RESULT_GUARD(s2n_write_fd_formatted(fd, "- kem groups:\n"));
        for (size_t i = 0; i < policy->kem_preferences->tls13_kem_group_count; i++) {
            RESULT_GUARD(s2n_write_fd_formatted(fd, "-- %s\n",
                    policy->kem_preferences->tls13_kem_groups[i]->name));
        }
    }

    return S2N_RESULT_OK;
}

int s2n_security_policy_write_verbose(const struct s2n_security_policy *policy,
        s2n_policy_format format, int fd)
{
    POSIX_ENSURE_REF(policy);
    POSIX_ENSURE(fd >= 0, S2N_ERR_INVALID_ARGUMENT);

    switch (format) {
        case S2N_POLICY_FORMAT_V1:
            POSIX_GUARD_RESULT(s2n_security_policy_write_format_v1(policy, fd));
            break;
        default:
            POSIX_BAIL(S2N_ERR_INVALID_ARGUMENT);
    }

    return S2N_SUCCESS;
}
