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

#include "tls/policy/s2n_policy_feature.h"
#include "tls/s2n_security_policies.h"

struct s2n_security_policy_builder {
    const struct s2n_security_policy *base_policy;
};

/* All our lists behave the same, but use different types and field names.
 * Use a macro to avoid writing multiple copies of the same basic methods.
 */
#define S2N_DEFINE_PREFERENCE_LIST_FUNCTIONS(pref_type, entry_type, list_name, count_name)              \
    static S2N_RESULT pref_type##_copy(const struct pref_type *original, const struct pref_type **copy) \
    {                                                                                                   \
        RESULT_ENSURE_REF(copy);                                                                        \
        if (original == NULL) {                                                                         \
            *copy = NULL;                                                                               \
            return S2N_RESULT_OK;                                                                       \
        }                                                                                               \
        DEFER_CLEANUP(struct s2n_blob pref_mem = { 0 }, s2n_free);                                      \
        RESULT_GUARD_POSIX(s2n_alloc(&pref_mem, sizeof(struct pref_type)));                             \
        RESULT_CHECKED_MEMCPY(pref_mem.data, original, pref_mem.size);                                  \
                                                                                                        \
        DEFER_CLEANUP(struct s2n_blob list_mem = { 0 }, s2n_free);                                      \
        size_t list_mem_size = original->count_name * sizeof(entry_type);                               \
        RESULT_GUARD_POSIX(s2n_alloc(&list_mem, list_mem_size));                                        \
        RESULT_CHECKED_MEMCPY(list_mem.data, original->list_name, list_mem.size);                       \
                                                                                                        \
        struct pref_type *prefs = (struct pref_type *) (void *) pref_mem.data;                          \
        prefs->list_name = (entry_type *) (void *) list_mem.data;                                       \
        *copy = prefs;                                                                                  \
                                                                                                        \
        ZERO_TO_DISABLE_DEFER_CLEANUP(pref_mem);                                                        \
        ZERO_TO_DISABLE_DEFER_CLEANUP(list_mem);                                                        \
        return S2N_RESULT_OK;                                                                           \
    }                                                                                                   \
                                                                                                        \
    static S2N_CLEANUP_RESULT pref_type##_free(const struct pref_type **prefs_ptr)                      \
    {                                                                                                   \
        if (!prefs_ptr) {                                                                               \
            return S2N_RESULT_OK;                                                                       \
        }                                                                                               \
        const struct pref_type *prefs = *prefs_ptr;                                                     \
        if (!prefs) {                                                                                   \
            return S2N_RESULT_OK;                                                                       \
        }                                                                                               \
        size_t size = prefs->count_name * sizeof(entry_type);                                           \
        /* Safety: we only free preferences allocated by the builder, so stripping
         * the `const` in order to free is a known safe mutation.
         */                      \
        RESULT_GUARD_POSIX(s2n_free_object(                                                             \
                (uint8_t **) (void *) (uintptr_t) (const void *) &prefs->list_name, size));             \
        RESULT_GUARD_POSIX(s2n_free_object(                                                             \
                (uint8_t **) (void *) (uintptr_t) (const void *) prefs_ptr, sizeof(struct pref_type))); \
        return S2N_RESULT_OK;                                                                           \
    }

S2N_DEFINE_PREFERENCE_LIST_FUNCTIONS(
        s2n_cipher_preferences, struct s2n_cipher_suite *, suites, count)
S2N_DEFINE_PREFERENCE_LIST_FUNCTIONS(
        s2n_signature_preferences, const struct s2n_signature_scheme *const, signature_schemes, count)
S2N_DEFINE_PREFERENCE_LIST_FUNCTIONS(
        s2n_ecc_preferences, const struct s2n_ecc_named_curve *const, ecc_curves, count)
S2N_DEFINE_PREFERENCE_LIST_FUNCTIONS(
        s2n_certificate_key_preferences, const struct s2n_certificate_key *const, certificate_keys, count)
/* s2n_kem_preferences actually has two lists, but the `kems` list is deprecated
 * and no longer set for any policies. */
S2N_DEFINE_PREFERENCE_LIST_FUNCTIONS(
        s2n_kem_preferences, const struct s2n_kem_group *, tls13_kem_groups, tls13_kem_group_count)

/* Safety: this method does not break if new lists are added to s2n_security_policy.
 * The copy will simply inherit the static version of the new list from the original,
 * just like it inherits the values of non-list fields.
 * The only requirement is that s2n_security_policy_free free every list created
 * by s2n_security_policy_copy.
 */
static S2N_RESULT s2n_security_policy_copy(const struct s2n_security_policy *original, struct s2n_security_policy **copy)
{
    RESULT_ENSURE_REF(original);
    RESULT_ENSURE_REF(copy);
    RESULT_ENSURE_EQ(*copy, NULL);

    struct s2n_blob mem = { 0 };
    RESULT_GUARD_POSIX(s2n_alloc(&mem, sizeof(struct s2n_security_policy)));
    DEFER_CLEANUP(struct s2n_security_policy *policy =
                          (struct s2n_security_policy *) (void *) mem.data,
            s2n_security_policy_free);
    RESULT_CHECKED_MEMCPY(mem.data, original, mem.size);
    policy->alloced = true;

    /* No existing policy still has TLS1.2 KEMs. Ignore them for simplicity. */
    RESULT_ENSURE(original->kem_preferences->kem_count == 0, S2N_ERR_DEPRECATED_SECURITY_POLICY);

    RESULT_GUARD(s2n_cipher_preferences_copy(
            original->cipher_preferences, &policy->cipher_preferences));
    RESULT_GUARD(s2n_signature_preferences_copy(
            original->signature_preferences, &policy->signature_preferences));
    RESULT_GUARD(s2n_signature_preferences_copy(
            original->certificate_signature_preferences, &policy->certificate_signature_preferences));
    RESULT_GUARD(s2n_ecc_preferences_copy(
            original->ecc_preferences, &policy->ecc_preferences));
    RESULT_GUARD(s2n_certificate_key_preferences_copy(
            original->certificate_key_preferences, &policy->certificate_key_preferences));
    RESULT_GUARD(s2n_kem_preferences_copy(
            original->kem_preferences, &policy->kem_preferences));

    *copy = policy;
    ZERO_TO_DISABLE_DEFER_CLEANUP(policy);
    return S2N_RESULT_OK;
}

int s2n_security_policy_free(struct s2n_security_policy **policy_ptr)
{
    if (!policy_ptr) {
        return S2N_SUCCESS;
    }
    struct s2n_security_policy *policy = *policy_ptr;
    if (!policy) {
        return S2N_SUCCESS;
    }

    /* Static policies should always be const, so this method's non-const
     * argument should prevent mistakes. However, there are ways to circumvent
     * const in C, so add an extra safety check.
     */
    POSIX_ENSURE(policy->alloced, S2N_ERR_INVALID_ARGUMENT);

    POSIX_GUARD_RESULT(s2n_cipher_preferences_free(&policy->cipher_preferences));
    POSIX_GUARD_RESULT(s2n_signature_preferences_free(&policy->signature_preferences));
    POSIX_GUARD_RESULT(s2n_signature_preferences_free(&policy->certificate_signature_preferences));
    POSIX_GUARD_RESULT(s2n_ecc_preferences_free(&policy->ecc_preferences));
    POSIX_GUARD_RESULT(s2n_certificate_key_preferences_free(&policy->certificate_key_preferences));
    POSIX_GUARD_RESULT(s2n_kem_preferences_free(&policy->kem_preferences));

    POSIX_GUARD(s2n_free_object((uint8_t **) policy_ptr, sizeof(struct s2n_security_policy)));
    return S2N_SUCCESS;
}

struct s2n_security_policy_builder *s2n_security_policy_builder_from_version(const char *version)
{
    PTR_ENSURE(version, S2N_ERR_INVALID_ARGUMENT);
    DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
    PTR_GUARD_POSIX(s2n_alloc(&mem, sizeof(struct s2n_security_policy_builder)));
    struct s2n_security_policy_builder *builder =
            (struct s2n_security_policy_builder *) (void *) mem.data;

    PTR_GUARD_POSIX(s2n_find_security_policy_from_version(version, &builder->base_policy));
    PTR_ENSURE_REF(builder->base_policy);
    PTR_ENSURE_EQ(builder->base_policy->alloced, false);

    ZERO_TO_DISABLE_DEFER_CLEANUP(mem);
    return builder;
}

int s2n_security_policy_builder_free(struct s2n_security_policy_builder **builder_ptr)
{
    if (!builder_ptr) {
        return S2N_SUCCESS;
    }
    POSIX_GUARD(s2n_free_object((uint8_t **) builder_ptr, sizeof(struct s2n_security_policy_builder)));
    return S2N_SUCCESS;
}

/* For now, "build" just copies the input policy.
 * We will add functionality later.
 */
struct s2n_security_policy *s2n_security_policy_build(struct s2n_security_policy_builder *builder)
{
    PTR_ENSURE(builder, S2N_ERR_INVALID_ARGUMENT);
    struct s2n_security_policy *policy = NULL;
    PTR_GUARD_RESULT(s2n_security_policy_copy(builder->base_policy, &policy));
    PTR_ENSURE_REF(policy);
    return policy;
}
