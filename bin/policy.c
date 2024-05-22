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

#include <stdint.h>
#include <stdlib.h>

#include "api/s2n.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_security_rules.h"

#define BOOL_STR(b) ((b) ? "yes" : "no")

extern const struct s2n_security_rule security_rule_definitions[S2N_SECURITY_RULES_COUNT];

const char *version_strs[] = {
    [S2N_SSLv2] = "SSLv2",
    [S2N_SSLv3] = "SSLv3",
    [S2N_TLS10] = "TLS1.0",
    [S2N_TLS11] = "TLS1.1",
    [S2N_TLS12] = "TLS1.2",
    [S2N_TLS13] = "TLS1.3",
};

static int usage()
{
    printf("policy <version>\n"
           "example: policy default_tls13\n\n");
    return 0;
}

int main(int argc, char *const *argv)
{
    if (argc != 2) {
        usage();
        exit(1);
    }

    const char *policy_name = argv[1];
    const struct s2n_security_policy *policy = NULL;
    if (s2n_find_security_policy_from_version(policy_name, &policy) != S2N_SUCCESS) {
        usage();
        exit(1);
    }

    printf("name: %s\n", policy_name);

    const char *version_str = version_strs[policy->minimum_protocol_version];
    printf("min version: %s\n", version_str ? version_str : "None");

    printf("rules:\n");
    for (size_t i = 0; i < S2N_SECURITY_RULES_COUNT; i++) {
        printf("- %s: %s\n", security_rule_definitions[i].name, BOOL_STR(policy->rules[i]));
    }

    printf("cipher suites:\n");
    if (policy->cipher_preferences->allow_chacha20_boosting) {
        printf("- chacha20 boosting enabled\n");
    }
    for (size_t i = 0; i < policy->cipher_preferences->count; i++) {
        printf("- %s\n", policy->cipher_preferences->suites[i]->iana_name);
    }

    printf("signature schemes:\n");
    for (size_t i = 0; i < policy->signature_preferences->count; i++) {
        printf("- %s\n", policy->signature_preferences->signature_schemes[i]->iana_name);
    }

    printf("curves:\n");
    for (size_t i = 0; i < policy->ecc_preferences->count; i++) {
        printf("- %s\n", policy->ecc_preferences->ecc_curves[i]->name);
    }

    if (policy->certificate_signature_preferences) {
        if (policy->certificate_preferences_apply_locally) {
            printf("certificate preferences apply locally\n");
        }
        printf("certificate signature schemes:\n");
        for (size_t i = 0; i < policy->certificate_signature_preferences->count; i++) {
            printf("- %s\n", policy->certificate_signature_preferences->signature_schemes[i]->iana_name);
        }
    }

    if (policy->certificate_key_preferences) {
        printf("certificate keys:\n");
        for (size_t i = 0; i < policy->certificate_key_preferences->count; i++) {
            printf("- %s\n", policy->certificate_key_preferences->certificate_keys[i]->name);
        }
    }

    if (policy->kem_preferences && policy->kem_preferences != &kem_preferences_null) {
        printf("pq:\n");
        printf("- revision: %i\n", policy->kem_preferences->tls13_pq_hybrid_draft_revision);
        printf("- kems:\n");
        for (size_t i = 0; i < policy->kem_preferences->kem_count; i++) {
            printf("-- %s\n", policy->kem_preferences->kems[i]->name);
        }
        printf("- kem groups:\n");
        for (size_t i = 0; i < policy->kem_preferences->tls13_kem_group_count; i++) {
            printf("-- %s\n", policy->kem_preferences->tls13_kem_groups[i]->name);
        }
    }

    return 0;
}
