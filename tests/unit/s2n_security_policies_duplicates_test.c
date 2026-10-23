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

#include "crypto/s2n_ecc_evp.h"
#include "s2n_test.h"
#include "tls/s2n_security_policies.h"

/*
 * Two policy names can describe the same thing in two ways, and this test requires
 * both to be declared.
 *
 * Several names may point at one definition. That is the right way to express "these
 * names mean the same thing", but it also means a caller asking for either name gets
 * the same policy, so it needs to be deliberate rather than accidental. Those name
 * sets are declared in allowed_alias_groups.
 *
 * Separate definitions may instead hold identical content. Those cost memory and
 * drift apart when only one of them is updated, so they should be consolidated into
 * a single definition. The pairs that exist today are declared in allowed_duplicates.
 *
 * Any pair of policies falling into either category without being declared below
 * fails the test.
 */

/* The largest declared alias group. Raise this to declare a larger one. */
#define S2N_MAX_POLICY_ALIAS_NAMES 4

/* Names of policies that intentionally share one definition. Unused entries are NULL. */
struct s2n_policy_alias_group {
    const char *names[S2N_MAX_POLICY_ALIAS_NAMES];
};

struct s2n_policy_pair {
    const char *policy_a;
    const char *policy_b;
};

static const struct s2n_policy_alias_group allowed_alias_groups[] = {
    /* Each "default" name tracks whichever dated policy is currently recommended,
     * so it shares that policy's definition. */
    { { "default", "20251014" } },
    { { "default_tls13", "20240503" } },
    { { "default_fips", "20251015" } },
    { { "default_pq", "20250721" } },

    /* Names of the standard a dated policy implements. */
    { { "rfc9151", "cnsa_1", "20251013" } },
    { { "cnsa_2", "20260219" } },
    /* 20260220 also ships under an ELB name, so all three names are one group. */
    { { "cnsa_1_2_interop", "20260220", "ELBSecurityPolicy-TLS13-1-2-CNSA2-INTEROP2-FIPS-PQ-2026-07" } },

    /* ELB names for dated policies. The ELB name is listed first in
     * security_policy_selection, so it is the name reported by
     * s2n_find_version_from_security_policy(). */
    { { "ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP1-FIPS-2023-07", "20251113" } },
    { { "ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP2-FIPS-2023-07", "20251117" } },
    { { "ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP3-FIPS-2023-07", "20251114" } },
    { { "ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP4-FIPS-2023-07", "20251115" } },
    { { "ELBSecurityPolicy-TLS13-1-3-CNSA2-INTEROP1-FIPS-PQ-2026-07", "20260720" } },
    /* INTEROP2 shares 20260220, so it is declared with cnsa_1_2_interop above. */
    { { "ELBSecurityPolicy-TLS13-1-2-CNSA2-INTEROP3-FIPS-PQ-2026-07", "20260722" } },

    /* Not a mistake, as noted in security_policy_selection: ELB shipped these two
     * names for the same policy. */
    { { "ELBSecurityPolicy-TLS-1-0-2015-05", "ELBSecurityPolicy-2016-08" } },
};

static const size_t allowed_alias_groups_count = s2n_array_len(allowed_alias_groups);

static const struct s2n_policy_pair allowed_duplicates[] = {
    /* Defined field-for-field identically to security_policy_20241001, with no
     * comment recording an intended difference. */
    {
            .policy_a = "20241001",
            .policy_b = "20241001_pq_mixed",
    },
    /* These three pairs are each a base policy and a variant added to introduce
     * IETF standard KEM groups. The base policies have since moved onto those same
     * KEM groups, so each variant now matches the policy it was derived from.
     * Policy names are public API, so neither name can simply be dropped. */
    {
            .policy_a = "AWS-CRT-SDK-TLSv1.2-2023-PQ",
            .policy_b = "AWS-CRT-SDK-TLSv1.2-2025-PQ",
    },
    {
            .policy_a = "CloudFront-TLS-1-0-2014",
            .policy_b = "CloudFront-TLS-1-0-2014-PQ-Beta",
    },
    {
            .policy_a = "CloudFront-TLS-1-2-2021-no-sha1",
            .policy_b = "CloudFront-TLS-1-2-2021-no-sha1-PQ-Beta",
    },
#if !EVP_APIS_SUPPORTED
    /* The pairs below are distinguished only by x25519, so they are duplicates
     * exactly on the libcryptos that compile x25519 out of the curve preferences:
     * openssl-1.0.2, LibreSSL and BoringSSL.
     *
     * s2n_ecc_pref_list_20200310 is x25519, p256, p384. s2n_ecc_pref_list_20230623
     * is p256, x25519, p384, differing only in where x25519 sits.
     * s2n_ecc_pref_list_20140601 is p256, p384. Drop x25519 and all three become
     * the same list.
     *
     * Each AWS-CRT-SDK pair below is 20200310 against 20230623, and
     * 20190801/20190802 is 20200310 against 20140601. */
    {
            .policy_a = "AWS-CRT-SDK-SSLv3.0",
            .policy_b = "AWS-CRT-SDK-SSLv3.0-2023",
    },
    {
            .policy_a = "AWS-CRT-SDK-TLSv1.0",
            .policy_b = "AWS-CRT-SDK-TLSv1.0-2023",
    },
    {
            .policy_a = "AWS-CRT-SDK-TLSv1.1",
            .policy_b = "AWS-CRT-SDK-TLSv1.1-2023",
    },
    {
            .policy_a = "AWS-CRT-SDK-TLSv1.2",
            .policy_b = "AWS-CRT-SDK-TLSv1.2-2023",
    },
    {
            .policy_a = "AWS-CRT-SDK-TLSv1.3",
            .policy_b = "AWS-CRT-SDK-TLSv1.3-2023",
    },
    {
            .policy_a = "20190801",
            .policy_b = "20190802",
    },
#endif
};

static const size_t allowed_duplicates_count = s2n_array_len(allowed_duplicates);

/* Matches a pair of policy names against the list in either order. */
static S2N_RESULT s2n_policy_pair_in_list(const char *name_a, const char *name_b,
        const struct s2n_policy_pair *list, size_t list_count, bool *val)
{
    RESULT_ENSURE_REF(name_a);
    RESULT_ENSURE_REF(name_b);
    RESULT_ENSURE_REF(list);
    RESULT_ENSURE_MUT(val);

    *val = false;
    for (size_t i = 0; i < list_count; i++) {
        RESULT_ENSURE_REF(list[i].policy_a);
        RESULT_ENSURE_REF(list[i].policy_b);

        bool forward = strcmp(name_a, list[i].policy_a) == 0
                && strcmp(name_b, list[i].policy_b) == 0;
        bool reverse = strcmp(name_a, list[i].policy_b) == 0
                && strcmp(name_b, list[i].policy_a) == 0;

        if (forward || reverse) {
            *val = true;
            return S2N_RESULT_OK;
        }
    }
    return S2N_RESULT_OK;
}

/* Reports whether a single alias group declares both names. */
static S2N_RESULT s2n_policy_alias_group_contains(const struct s2n_policy_alias_group *group,
        const char *name_a, const char *name_b, bool *val)
{
    RESULT_ENSURE_REF(group);
    RESULT_ENSURE_REF(name_a);
    RESULT_ENSURE_REF(name_b);
    RESULT_ENSURE_MUT(val);

    bool found_a = false;
    bool found_b = false;
    for (size_t i = 0; i < S2N_MAX_POLICY_ALIAS_NAMES && group->names[i] != NULL; i++) {
        found_a = found_a || strcmp(name_a, group->names[i]) == 0;
        found_b = found_b || strcmp(name_b, group->names[i]) == 0;
    }

    *val = found_a && found_b;
    return S2N_RESULT_OK;
}

/* Reports whether any alias group declares both names. */
static S2N_RESULT s2n_policy_pair_is_declared_alias(const char *name_a, const char *name_b,
        const struct s2n_policy_alias_group *groups, size_t group_count, bool *val)
{
    RESULT_ENSURE_REF(groups);
    RESULT_ENSURE_MUT(val);

    *val = false;
    for (size_t i = 0; i < group_count; i++) {
        bool declared = false;
        RESULT_GUARD(s2n_policy_alias_group_contains(&groups[i], name_a, name_b, &declared));
        if (declared) {
            *val = true;
            return S2N_RESULT_OK;
        }
    }
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_security_policy_equals() must compare every field of the struct. If a
     * field is added and the comparison is not updated, differing policies would
     * silently report as equal and this test would stop catching duplicates.
     * Adding a field changes the size of the struct, which trips this check.
     *
     * On a change here: update s2n_security_policy_equals(), then update this size.
     */
    {
#if defined(__LP64__) || defined(_WIN64)
        EXPECT_EQUAL(sizeof(struct s2n_security_policy), 72);
#endif
    }

    /* No two policy definitions are equal unless the pair is allowed above */
    {
        size_t unlisted_count = 0;
        size_t undeclared_alias_count = 0;

        for (size_t i = 0; security_policy_selection[i].version != NULL; i++) {
            const char *name_a = security_policy_selection[i].version;
            const struct s2n_security_policy *policy_a = security_policy_selection[i].security_policy;
            EXPECT_NOT_NULL(policy_a);

            for (size_t j = i + 1; security_policy_selection[j].version != NULL; j++) {
                const char *name_b = security_policy_selection[j].version;
                const struct s2n_security_policy *policy_b = security_policy_selection[j].security_policy;
                EXPECT_NOT_NULL(policy_b);

                /* Sharing one definition makes these names interchangeable to a
                 * caller, so it has to be declared rather than inferred. */
                if (policy_a == policy_b) {
                    bool declared = false;
                    EXPECT_OK(s2n_policy_pair_is_declared_alias(name_a, name_b,
                            allowed_alias_groups, allowed_alias_groups_count, &declared));
                    if (!declared) {
                        fprintf(stdout, "Security policies '%s' and '%s' share a single "
                                        "definition but are not declared as aliases.\n",
                                name_a, name_b);
                        undeclared_alias_count++;
                    }
                    continue;
                }

                bool equal = false;
                EXPECT_OK(s2n_security_policy_equals(policy_a, policy_b, &equal));
                if (!equal) {
                    continue;
                }

                bool allowed = false;
                EXPECT_OK(s2n_policy_pair_in_list(name_a, name_b, allowed_duplicates,
                        allowed_duplicates_count, &allowed));
                if (allowed) {
                    continue;
                }

                fprintf(stdout, "Security policies '%s' and '%s' are separate definitions "
                                "with identical contents.\n",
                        name_a, name_b);
                unlisted_count++;
            }
        }

        if (undeclared_alias_count > 0) {
            fprintf(stdout, "Found %zu undeclared security policy alias pair(s). Add the "
                            "names to a single allowed_alias_groups entry with a reason.\n",
                    undeclared_alias_count);
        }
        if (unlisted_count > 0) {
            fprintf(stdout, "Found %zu duplicate security policy definition(s). Point both "
                            "names at a single definition, or add the pair to "
                            "allowed_duplicates with a reason.\n",
                    unlisted_count);
        }
        if (undeclared_alias_count > 0 || unlisted_count > 0) {
            FAIL_MSG("Undeclared security policy aliases or duplicate definitions detected");
        }
    }

    /* Every declared alias group still shares one definition, so the list cannot go stale */
    {
        for (size_t i = 0; i < allowed_alias_groups_count; i++) {
            const struct s2n_policy_alias_group *group = &allowed_alias_groups[i];

            const struct s2n_security_policy *first_policy = NULL;
            size_t name_count = 0;

            for (size_t j = 0; j < S2N_MAX_POLICY_ALIAS_NAMES && group->names[j] != NULL; j++) {
                const char *name = group->names[j];

                const struct s2n_security_policy *policy = NULL;
                EXPECT_SUCCESS(s2n_find_security_policy_from_version(name, &policy));
                EXPECT_NOT_NULL(policy);
                name_count++;

                if (first_policy == NULL) {
                    first_policy = policy;
                    continue;
                }
                if (policy != first_policy) {
                    fprintf(stdout, "Declared alias '%s' no longer shares a definition with "
                                    "'%s'. Split or remove the allowed_alias_groups entry.\n",
                            name, group->names[0]);
                    FAIL_MSG("Stale entry in allowed_alias_groups");
                }
            }

            /* A group naming fewer than two policies declares nothing. */
            EXPECT_TRUE(name_count >= 2);
        }
    }

    /* Every allowed pair is still a duplicate, so the list cannot go stale */
    {
        for (size_t i = 0; i < allowed_duplicates_count; i++) {
            const char *name_a = allowed_duplicates[i].policy_a;
            const char *name_b = allowed_duplicates[i].policy_b;

            const struct s2n_security_policy *policy_a = NULL;
            const struct s2n_security_policy *policy_b = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version(name_a, &policy_a));
            EXPECT_SUCCESS(s2n_find_security_policy_from_version(name_b, &policy_b));
            EXPECT_NOT_NULL(policy_a);
            EXPECT_NOT_NULL(policy_b);

            /* Pairs sharing a definition are skipped by the check above, so listing
             * one here would have no effect. */
            if (policy_a == policy_b) {
                fprintf(stdout, "Allowed pair '%s' and '%s' now share a single definition. "
                                "Remove the entry from allowed_duplicates.\n",
                        name_a, name_b);
                FAIL_MSG("Stale entry in allowed_duplicates");
            }

            bool equal = false;
            EXPECT_OK(s2n_security_policy_equals(policy_a, policy_b, &equal));
            if (!equal) {
                fprintf(stdout, "Allowed pair '%s' and '%s' is no longer a duplicate. "
                                "Remove the entry from allowed_duplicates.\n",
                        name_a, name_b);
                FAIL_MSG("Stale entry in allowed_duplicates");
            }
        }
    }

    /* s2n_security_policy_equals() rejects NULL arguments */
    {
        const struct s2n_security_policy *policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));

        bool equal = false;
        EXPECT_ERROR_WITH_ERRNO(s2n_security_policy_equals(NULL, policy, &equal), S2N_ERR_NULL);
        EXPECT_ERROR_WITH_ERRNO(s2n_security_policy_equals(policy, NULL, &equal), S2N_ERR_NULL);
        EXPECT_ERROR_WITH_ERRNO(s2n_security_policy_equals(policy, policy, NULL), S2N_ERR_NULL);
    }

    /* Every policy equals itself */
    {
        for (size_t i = 0; security_policy_selection[i].version != NULL; i++) {
            const struct s2n_security_policy *policy = security_policy_selection[i].security_policy;
            EXPECT_NOT_NULL(policy);

            bool equal = false;
            EXPECT_OK(s2n_security_policy_equals(policy, policy, &equal));
            EXPECT_TRUE(equal);
        }
    }

    END_TEST();
}
