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

#define BOOL_STR(b) ((b) ? "yes" : "no")

extern const struct s2n_security_rule security_rule_definitions[S2N_SECURITY_RULES_COUNT];

static const char *version_strs[] = {
    [S2N_SSLv2] = "SSLv2",
    [S2N_SSLv3] = "SSLv3",
    [S2N_TLS10] = "TLS1.0",
    [S2N_TLS11] = "TLS1.1",
    [S2N_TLS12] = "TLS1.2",
    [S2N_TLS13] = "TLS1.3",
};

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

/* Helper function to write a formatted string to a file descriptor */
static int s2n_write_fd_formatted(int fd, const char *format, ...)
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
        POSIX_BAIL(S2N_ERR_INVALID_ARGUMENT);
    }

    /* Allocate buffer and format string */
    DEFER_CLEANUP(struct s2n_blob buffer = { 0 }, s2n_free);
    POSIX_GUARD(s2n_alloc(&buffer, len + 1));
    int result = vsnprintf((char *) buffer.data, buffer.size, format, args);
    va_end(args);

    if (result < 0 || result >= (int) buffer.size) {
        POSIX_BAIL(S2N_ERR_INVALID_ARGUMENT);
    }

    /* Write to file descriptor */
    ssize_t written = write(fd, buffer.data, len);
    if (written != len) {
        POSIX_BAIL(S2N_ERR_IO);
    }

    return S2N_SUCCESS;
}

/* Write verbose policy output in FORMAT_V1 style */
static int s2n_policy_write_format_v1(const struct s2n_security_policy *policy, const char *policy_name, int fd)
{
    POSIX_ENSURE_REF(policy);
    POSIX_ENSURE_REF(policy_name);

    POSIX_GUARD(s2n_write_fd_formatted(fd, "name: %s\n", policy_name));

    const char *version_str = version_strs[policy->minimum_protocol_version];
    POSIX_GUARD(s2n_write_fd_formatted(fd, "min version: %s\n", version_str ? version_str : "None"));

    POSIX_GUARD(s2n_write_fd_formatted(fd, "rules:\n"));
    for (size_t i = 0; i < S2N_SECURITY_RULES_COUNT; i++) {
        POSIX_GUARD(s2n_write_fd_formatted(fd, "- %s: %s\n",
                security_rule_definitions[i].name, BOOL_STR(policy->rules[i])));
    }

    POSIX_GUARD(s2n_write_fd_formatted(fd, "cipher suites:\n"));
    if (policy->cipher_preferences->allow_chacha20_boosting) {
        POSIX_GUARD(s2n_write_fd_formatted(fd, "- chacha20 boosting enabled\n"));
    }
    for (size_t i = 0; i < policy->cipher_preferences->count; i++) {
        POSIX_GUARD(s2n_write_fd_formatted(fd, "- %s\n", policy->cipher_preferences->suites[i]->iana_name));
    }

    POSIX_GUARD(s2n_write_fd_formatted(fd, "signature schemes:\n"));
    for (size_t i = 0; i < policy->signature_preferences->count; i++) {
        POSIX_GUARD(s2n_write_fd_formatted(fd, "- %s\n", policy->signature_preferences->signature_schemes[i]->name));
    }

    POSIX_GUARD(s2n_write_fd_formatted(fd, "curves:\n"));
    for (size_t i = 0; i < policy->ecc_preferences->count; i++) {
        POSIX_GUARD(s2n_write_fd_formatted(fd, "- %s\n", policy->ecc_preferences->ecc_curves[i]->name));
    }

    if (policy->certificate_signature_preferences) {
        if (policy->certificate_preferences_apply_locally) {
            POSIX_GUARD(s2n_write_fd_formatted(fd, "certificate preferences apply locally\n"));
        }
        POSIX_GUARD(s2n_write_fd_formatted(fd, "certificate signature schemes:\n"));
        for (size_t i = 0; i < policy->certificate_signature_preferences->count; i++) {
            POSIX_GUARD(s2n_write_fd_formatted(fd, "- %s\n",
                    policy->certificate_signature_preferences->signature_schemes[i]->name));
        }
    }

    if (policy->certificate_key_preferences) {
        POSIX_GUARD(s2n_write_fd_formatted(fd, "certificate keys:\n"));
        for (size_t i = 0; i < policy->certificate_key_preferences->count; i++) {
            POSIX_GUARD(s2n_write_fd_formatted(fd, "- %s\n",
                    policy->certificate_key_preferences->certificate_keys[i]->name));
        }
    }

    extern const struct s2n_kem_preferences kem_preferences_null;
    if (policy->kem_preferences && policy->kem_preferences != &kem_preferences_null) {
        POSIX_GUARD(s2n_write_fd_formatted(fd, "pq:\n"));
        POSIX_GUARD(s2n_write_fd_formatted(fd, "- revision: %i\n",
                policy->kem_preferences->tls13_pq_hybrid_draft_revision));

        if (policy->kem_preferences->kem_count > 0) {
            POSIX_GUARD(s2n_write_fd_formatted(fd, "- kems:\n"));
            for (size_t i = 0; i < policy->kem_preferences->kem_count; i++) {
                POSIX_GUARD(s2n_write_fd_formatted(fd, "-- %s\n",
                        policy->kem_preferences->kems[i]->name));
            }
        }

        POSIX_GUARD(s2n_write_fd_formatted(fd, "- kem groups:\n"));
        for (size_t i = 0; i < policy->kem_preferences->tls13_kem_group_count; i++) {
            POSIX_GUARD(s2n_write_fd_formatted(fd, "-- %s\n",
                    policy->kem_preferences->tls13_kem_groups[i]->name));
        }
    }

    return S2N_SUCCESS;
}

int s2n_policy_builder_write_verbose(struct s2n_security_policy_builder *builder,
        s2n_policy_format format, int fd)
{
    POSIX_ENSURE_REF(builder);
    POSIX_ENSURE(fd >= 0, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE_REF(builder->base_policy);

    /* TODO: Currently outputs the base_policy. This needs to be updated once builder implements a "finalized" policy field */
    const char *policy_name = "unknown";
    extern struct s2n_security_policy_selection security_policy_selection[];
    for (size_t i = 0; security_policy_selection[i].version != NULL; i++) {
        if (security_policy_selection[i].security_policy == builder->base_policy) {
            policy_name = security_policy_selection[i].version;
            break;
        }
    }

    switch (format) {
        case S2N_POLICY_FORMAT_V1:
            POSIX_GUARD(s2n_policy_write_format_v1(builder->base_policy, policy_name, fd));
            break;
        default:
            POSIX_BAIL(S2N_ERR_INVALID_ARGUMENT);
    }

    return S2N_SUCCESS;
}
