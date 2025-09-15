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

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/policy/s2n_policy_feature.h"

static S2N_RESULT s2n_verify_format_v1_output(const char *output, const char *policy_name)
{
    RESULT_ENSURE_REF(output);
    RESULT_ENSURE_REF(policy_name);

    /* Required sections are present */
    RESULT_ENSURE(strstr(output, "min version: ") != NULL, S2N_ERR_TEST_ASSERTION);
    RESULT_ENSURE(strstr(output, "rules:\n") != NULL, S2N_ERR_TEST_ASSERTION);
    RESULT_ENSURE(strstr(output, "cipher suites:\n") != NULL, S2N_ERR_TEST_ASSERTION);
    RESULT_ENSURE(strstr(output, "signature schemes:\n") != NULL, S2N_ERR_TEST_ASSERTION);
    RESULT_ENSURE(strstr(output, "curves:\n") != NULL, S2N_ERR_TEST_ASSERTION);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_capture_output_to_buffer(struct s2n_security_policy_builder *builder,
        s2n_policy_format format,
        char *buffer,
        size_t buffer_size)
{
    RESULT_ENSURE_REF(builder);
    RESULT_ENSURE_REF(buffer);
    RESULT_ENSURE(buffer_size > 0, S2N_ERR_INVALID_ARGUMENT);

    /* Use a pipe for capturing output */
    int pipe_fds[2] = { 0 };
    RESULT_ENSURE(pipe(pipe_fds) == 0, S2N_ERR_IO);
    int write_result = s2n_policy_builder_write_verbose(builder, format, pipe_fds[1]);
    close(pipe_fds[1]);
    RESULT_GUARD_POSIX(write_result);
    ssize_t bytes_read = read(pipe_fds[0], buffer, buffer_size - 1);
    close(pipe_fds[0]);
    RESULT_ENSURE(bytes_read > 0, S2N_ERR_IO);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_security_policies_assert_match(
        const struct s2n_security_policy *a, const struct s2n_security_policy *b)
{
    /* Compare cipher preferences */
    const struct s2n_cipher_preferences *a_cipher_prefs = a->cipher_preferences;
    const struct s2n_cipher_preferences *b_cipher_prefs = b->cipher_preferences;
    EXPECT_NOT_NULL(a_cipher_prefs);
    EXPECT_NOT_NULL(b_cipher_prefs);
    EXPECT_EQUAL(a_cipher_prefs->count, b_cipher_prefs->count);
    for (size_t i = 0; i < a_cipher_prefs->count; i++) {
        EXPECT_EQUAL(a_cipher_prefs->suites[i], b_cipher_prefs->suites[i]);
    }

    /* Compare signature preferences */
    const struct s2n_signature_preferences *a_sig_prefs = a->signature_preferences;
    const struct s2n_signature_preferences *b_sig_prefs = b->signature_preferences;
    EXPECT_NOT_NULL(a_sig_prefs);
    EXPECT_NOT_NULL(b_sig_prefs);
    EXPECT_EQUAL(a_sig_prefs->count, b_sig_prefs->count);
    for (size_t i = 0; i < a_sig_prefs->count; i++) {
        EXPECT_EQUAL(a_sig_prefs->signature_schemes[i], b_sig_prefs->signature_schemes[i]);
    }

    /* Compare certificate signature preferences */
    const struct s2n_signature_preferences *a_cert_sig_prefs = a->certificate_signature_preferences;
    const struct s2n_signature_preferences *b_cert_sig_prefs = b->certificate_signature_preferences;
    if (a_cert_sig_prefs) {
        EXPECT_NOT_NULL(b_cert_sig_prefs);
        EXPECT_EQUAL(a_cert_sig_prefs->count, b_cert_sig_prefs->count);
        for (size_t i = 0; i < a_cert_sig_prefs->count; i++) {
            EXPECT_EQUAL(a_cert_sig_prefs->signature_schemes[i], b_cert_sig_prefs->signature_schemes[i]);
        }
    } else {
        EXPECT_NULL(b_cert_sig_prefs);
    }

    /* Compare ecc curve preferences */
    const struct s2n_ecc_preferences *a_ecc_prefs = a->ecc_preferences;
    const struct s2n_ecc_preferences *b_ecc_prefs = b->ecc_preferences;
    EXPECT_NOT_NULL(a_ecc_prefs);
    EXPECT_NOT_NULL(b_ecc_prefs);
    EXPECT_EQUAL(a_ecc_prefs->count, b_ecc_prefs->count);
    for (size_t i = 0; i < a_ecc_prefs->count; i++) {
        EXPECT_EQUAL(a_ecc_prefs->ecc_curves[i], b_ecc_prefs->ecc_curves[i]);
    }

    /* Compare certificate key preferences */
    const struct s2n_certificate_key_preferences *a_key_prefs = a->certificate_key_preferences;
    const struct s2n_certificate_key_preferences *b_key_prefs = b->certificate_key_preferences;
    if (a_key_prefs) {
        EXPECT_NOT_NULL(b_key_prefs);
        EXPECT_EQUAL(a_key_prefs->count, b_key_prefs->count);
        for (size_t i = 0; i < a_key_prefs->count; i++) {
            EXPECT_EQUAL(a_key_prefs->certificate_keys[i], b_key_prefs->certificate_keys[i]);
        }
    } else {
        EXPECT_NULL(b_key_prefs);
    }

    /* Compare kem preferences */
    const struct s2n_kem_preferences *a_kem_prefs = a->kem_preferences;
    const struct s2n_kem_preferences *b_kem_prefs = b->kem_preferences;
    if (a_kem_prefs) {
        EXPECT_NOT_NULL(b_kem_prefs);
        EXPECT_EQUAL(a_kem_prefs->tls13_kem_group_count, b_kem_prefs->tls13_kem_group_count);
        for (size_t i = 0; i < a_kem_prefs->tls13_kem_group_count; i++) {
            EXPECT_EQUAL(a_kem_prefs->tls13_kem_groups[i], b_kem_prefs->tls13_kem_groups[i]);
        }
    } else {
        EXPECT_NULL(b_kem_prefs);
    }

    /* If we assume that the source code uses memcpy or similar instead of
     * setting individual fields, we don't have to ensure that EVERY field matches.
     * Checking a few fields should be sufficient.
     * That means that this test does not need to be updated with all new fields.
     * We should include one field from each preferences list, but the `count`
     * checks above should also handle that requirement.
     */
    EXPECT_EQUAL(a->minimum_protocol_version, b->minimum_protocol_version);
    EXPECT_EQUAL(a->rules[S2N_PERFECT_FORWARD_SECRECY], b->rules[S2N_PERFECT_FORWARD_SECRECY]);
    EXPECT_EQUAL(a_cipher_prefs->allow_chacha20_boosting, b_cipher_prefs->allow_chacha20_boosting);
    if (a_kem_prefs) {
        EXPECT_EQUAL(a_kem_prefs->tls13_pq_hybrid_draft_revision, b_kem_prefs->tls13_pq_hybrid_draft_revision);
    }

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: s2n_security_policy_builder_from_version / s2n_security_policy_builder_free */
    {
        /* Test: safety */
        {
            EXPECT_NULL_WITH_ERRNO(
                    s2n_security_policy_builder_from_version(NULL),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_SUCCESS(s2n_security_policy_builder_free(NULL));
            struct s2n_security_policy_builder *builder = NULL;
            EXPECT_SUCCESS(s2n_security_policy_builder_free(&builder));
        };

        /* Test: builder from invalid policy version */
        {
            EXPECT_NULL_WITH_ERRNO(
                    s2n_security_policy_builder_from_version("not_a_real_policy_version"),
                    S2N_ERR_INVALID_SECURITY_POLICY);
        };

        /* Test: successfully create and free a builder */
        {
            struct s2n_security_policy_builder *builder =
                    s2n_security_policy_builder_from_version("20250721");
            EXPECT_NOT_NULL(builder);

            EXPECT_SUCCESS(s2n_security_policy_builder_free(&builder));
            EXPECT_NULL(builder);

            /* Freeing again is a no-op */
            EXPECT_SUCCESS(s2n_security_policy_builder_free(&builder));
            EXPECT_NULL(builder);
        };
    };

    /* Test: s2n_security_policy_build / s2n_security_policy_free */
    {
        /* Test: safety */
        {
            EXPECT_NULL_WITH_ERRNO(
                    s2n_security_policy_build(NULL),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_SUCCESS(s2n_security_policy_free(NULL));
            struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_security_policy_free(&policy));
        };

        /* Test: successfully build and free a policy */
        {
            DEFER_CLEANUP(struct s2n_security_policy_builder *builder =
                                  s2n_security_policy_builder_from_version("20250721"),
                    s2n_security_policy_builder_free);
            EXPECT_NOT_NULL(builder);

            struct s2n_security_policy *policy = s2n_security_policy_build(builder);
            EXPECT_NOT_NULL(policy);
            EXPECT_TRUE(policy->alloced);

            EXPECT_SUCCESS(s2n_security_policy_free(&policy));
            EXPECT_NULL(policy);

            /* Freeing again is a no-op */
            EXPECT_SUCCESS(s2n_security_policy_free(&policy));
            EXPECT_NULL(policy);
        };

        /* Test: builder copies policies */
        {
            DEFER_CLEANUP(struct s2n_security_policy_builder *builder =
                                  s2n_security_policy_builder_from_version("20250721"),
                    s2n_security_policy_builder_free);
            EXPECT_NOT_NULL(builder);

            DEFER_CLEANUP(struct s2n_security_policy *copy =
                                  s2n_security_policy_build(builder),
                    s2n_security_policy_free);
            EXPECT_NOT_NULL(copy);

            const struct s2n_security_policy *original = &security_policy_20250721;
            EXPECT_OK(s2n_security_policies_assert_match(copy, original));
        };
    };

    /* Test: validate with all current static policies */
    for (size_t policy_index = 0; security_policy_selection[policy_index].version != NULL; policy_index++) {
        const char *version = security_policy_selection[policy_index].version;
        const struct s2n_security_policy *policy =
                security_policy_selection[policy_index].security_policy;

        /* Test: can create builder from all static policies */
        {
            struct s2n_security_policy_builder *builder =
                    s2n_security_policy_builder_from_version(version);
            EXPECT_NOT_NULL(builder);
            EXPECT_SUCCESS(s2n_security_policy_builder_free(&builder));
        };

        /* Test: can build with all static policies */
        {
            DEFER_CLEANUP(struct s2n_security_policy_builder *builder =
                                  s2n_security_policy_builder_from_version(version),
                    s2n_security_policy_builder_free);
            EXPECT_NOT_NULL(builder);

            struct s2n_security_policy *copy = s2n_security_policy_build(builder);
            EXPECT_NOT_NULL(copy);
            EXPECT_OK(s2n_security_policies_assert_match(copy, policy));
            EXPECT_SUCCESS(s2n_security_policy_free(&copy));
        };

        /* Test: cannot free any static policy */
        {
            struct s2n_security_policy *non_const_policy =
                    (struct s2n_security_policy *) (void *) (uintptr_t) (const void *) policy;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_free(&non_const_policy),
                    S2N_ERR_INVALID_ARGUMENT);
        };
    }

    /* Test: s2n_policy_builder_write_verbose */
    {
        /* Test: safety - NULL builder */
        {
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_policy_builder_write_verbose(NULL, S2N_POLICY_FORMAT_V1, STDOUT_FILENO),
                    S2N_ERR_NULL);
        };

        /* Test: safety - invalid format */
        {
            DEFER_CLEANUP(struct s2n_security_policy_builder *builder =
                                  s2n_security_policy_builder_from_version("default"),
                    s2n_security_policy_builder_free);
            EXPECT_NOT_NULL(builder);

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_policy_builder_write_verbose(builder, 999, STDOUT_FILENO),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Test: safety - invalid file descriptor */
        {
            DEFER_CLEANUP(struct s2n_security_policy_builder *builder =
                                  s2n_security_policy_builder_from_version("default"),
                    s2n_security_policy_builder_free);
            EXPECT_NOT_NULL(builder);

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_policy_builder_write_verbose(builder, S2N_POLICY_FORMAT_V1, -1),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Test: s2n_policy_builder_write_verbose - FORMAT_V1 structure verification */
        {
            /* Pick a few named policies for sanity checking. Snapshot tests verify the exact content. */
            const char *test_policies[] = {
                "default",
                "default_fips",
                "default_tls13",
                "default_pq",
                NULL
            };

            for (size_t i = 0; test_policies[i] != NULL; i++) {
                const char *policy_version = test_policies[i];

                DEFER_CLEANUP(struct s2n_security_policy_builder *builder =
                                      s2n_security_policy_builder_from_version(policy_version),
                        s2n_security_policy_builder_free);
                EXPECT_NOT_NULL(builder);

                char buffer[8192];
                EXPECT_OK(s2n_capture_output_to_buffer(builder, S2N_POLICY_FORMAT_V1, buffer, sizeof(buffer)));
                EXPECT_OK(s2n_verify_format_v1_output(buffer, policy_version));
            }
        };

        /* Test: write to stdout */
        {
            DEFER_CLEANUP(struct s2n_security_policy_builder *builder =
                                  s2n_security_policy_builder_from_version("default"),
                    s2n_security_policy_builder_free);
            EXPECT_NOT_NULL(builder);
            EXPECT_SUCCESS(s2n_policy_builder_write_verbose(builder, S2N_POLICY_FORMAT_V1, STDOUT_FILENO));
        };

        /* Test: write to file and verify content */
        {
            DEFER_CLEANUP(struct s2n_security_policy_builder *builder =
                                  s2n_security_policy_builder_from_version("default_tls13"),
                    s2n_security_policy_builder_free);
            EXPECT_NOT_NULL(builder);

            /* Create a temp file */
            char temp_filename[] = "/tmp/s2n_policy_test_XXXXXX";
            int temp_fd = mkstemp(temp_filename);
            EXPECT_TRUE(temp_fd >= 0);

            /* Write policy to file */
            EXPECT_SUCCESS(s2n_policy_builder_write_verbose(builder, S2N_POLICY_FORMAT_V1, temp_fd));
            EXPECT_SUCCESS(close(temp_fd));

            /* Read file content back */
            FILE *file = fopen(temp_filename, "r");
            EXPECT_NOT_NULL(file);
            char file_buffer[8192];
            size_t bytes_read = fread(file_buffer, 1, sizeof(file_buffer) - 1, file);
            EXPECT_TRUE(bytes_read > 0);
            fclose(file);

            EXPECT_OK(s2n_verify_format_v1_output(file_buffer, "default_tls13"));

            EXPECT_SUCCESS(unlink(temp_filename));
        };
    };

    END_TEST();
}
