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

#include "tls/s2n_security_rules.h"

#include "s2n_test.h"
#include "tls/s2n_cipher_preferences.h"

S2N_RESULT s2n_security_rule_validate_policy(
        const struct s2n_security_rule *rule,
        const struct s2n_security_policy *policy,
        struct s2n_security_rule_result *result);

struct s2n_cipher_suite *VALID_CIPHER_SUITE = &s2n_tls13_aes_256_gcm_sha384;
struct s2n_cipher_suite *EXAMPLE_INVALID_CIPHER_SUITE = &s2n_tls13_aes_128_gcm_sha256;
struct s2n_cipher_suite *EXAMPLE_INVALID_CIPHER_SUITE_2 = &s2n_tls13_chacha20_poly1305_sha256;
static S2N_RESULT s2n_test_cipher_suite_rule(const struct s2n_cipher_suite *cipher_suite, bool *valid)
{
    RESULT_ENSURE_REF(valid);
    if (cipher_suite == VALID_CIPHER_SUITE) {
        *valid = true;
    } else {
        *valid = false;
    }
    return S2N_RESULT_OK;
}

const struct s2n_signature_scheme *VALID_SIG_SCHEME = &s2n_ecdsa_sha256;
const struct s2n_signature_scheme *EXAMPLE_INVALID_SIG_SCHEME = &s2n_ecdsa_sha384;
static S2N_RESULT s2n_test_sig_scheme_rule(const struct s2n_signature_scheme *sig_scheme, bool *valid)
{
    RESULT_ENSURE_REF(valid);
    if (sig_scheme == VALID_SIG_SCHEME) {
        *valid = true;
    } else {
        *valid = false;
    }
    return S2N_RESULT_OK;
}

const struct s2n_ecc_named_curve *VALID_CURVE = &s2n_ecc_curve_secp256r1;
const struct s2n_ecc_named_curve *EXAMPLE_INVALID_CURVE = &s2n_ecc_curve_secp384r1;
static S2N_RESULT s2n_test_curve_rule(const struct s2n_ecc_named_curve *curve, bool *valid)
{
    RESULT_ENSURE_REF(valid);
    if (curve == VALID_CURVE) {
        *valid = true;
    } else {
        *valid = false;
    }
    return S2N_RESULT_OK;
}

const uint8_t VALID_VERSION = S2N_TLS12;
const uint8_t EXAMPLE_INVALID_VERSION = S2N_TLS11;
static S2N_RESULT s2n_test_version(uint8_t version, bool *valid)
{
    RESULT_ENSURE_REF(valid);
    if (version == VALID_VERSION) {
        *valid = true;
    } else {
        *valid = false;
    }
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const struct s2n_security_rule test_rule = {
        .name = "Test Rule",
        .validate_cipher_suite = s2n_test_cipher_suite_rule,
        .validate_sig_scheme = s2n_test_sig_scheme_rule,
        .validate_cert_sig_scheme = s2n_test_sig_scheme_rule,
        .validate_curve = s2n_test_curve_rule,
        .validate_version = s2n_test_version,
    };

    const struct s2n_cipher_preferences valid_cipher_prefs = {
        .suites = &VALID_CIPHER_SUITE,
        .count = 1,
    };
    struct s2n_cipher_suite *invalid_cipher_suites[] = {
        EXAMPLE_INVALID_CIPHER_SUITE,
        VALID_CIPHER_SUITE,
        EXAMPLE_INVALID_CIPHER_SUITE_2,
    };
    const struct s2n_cipher_preferences invalid_cipher_prefs = {
        .suites = invalid_cipher_suites,
        .count = s2n_array_len(invalid_cipher_suites),
    };

    const struct s2n_signature_preferences valid_sig_prefs = {
        .signature_schemes = &VALID_SIG_SCHEME,
        .count = 1,
    };
    const struct s2n_signature_preferences invalid_sig_prefs = {
        .signature_schemes = &EXAMPLE_INVALID_SIG_SCHEME,
        .count = 1,
    };

    const struct s2n_ecc_preferences valid_ecc_prefs = {
        .ecc_curves = &VALID_CURVE,
        .count = 1,
    };
    const struct s2n_ecc_preferences invalid_ecc_prefs = {
        .ecc_curves = &EXAMPLE_INVALID_CURVE,
        .count = 1,
    };

    const struct s2n_security_policy valid_policy = {
        .cipher_preferences = &valid_cipher_prefs,
        .signature_preferences = &valid_sig_prefs,
        .certificate_signature_preferences = &valid_sig_prefs,
        .ecc_preferences = &valid_ecc_prefs,
        .kem_preferences = &kem_preferences_null,
        .minimum_protocol_version = VALID_VERSION,
    };
    const struct s2n_security_policy invalid_policy = {
        .cipher_preferences = &invalid_cipher_prefs,
        .signature_preferences = &invalid_sig_prefs,
        .certificate_signature_preferences = &invalid_sig_prefs,
        .ecc_preferences = &invalid_ecc_prefs,
        .kem_preferences = &kem_preferences_null,
        .minimum_protocol_version = EXAMPLE_INVALID_VERSION,
    };

    /* Test s2n_security_rule_validate_policy */
    {
        /* Test: Marks valid policy as valid */
        {
            struct s2n_security_rule_result result = { 0 };
            EXPECT_OK(s2n_security_rule_validate_policy(
                    &test_rule, &valid_policy, &result));
            EXPECT_FALSE(result.found_error);
        };

        /* Test: Marks invalid policy as invalid */
        {
            /* Test: Entire policy invalid */
            {
                struct s2n_security_rule_result result = { 0 };
                EXPECT_OK(s2n_security_rule_validate_policy(
                        &test_rule, &invalid_policy, &result));
                EXPECT_TRUE(result.found_error);
            };

            /* Test: only cipher suite invalid */
            {
                struct s2n_security_policy test_policy = valid_policy;
                test_policy.cipher_preferences = &invalid_cipher_prefs;

                struct s2n_security_rule_result result = { 0 };
                EXPECT_OK(s2n_security_rule_validate_policy(
                        &test_rule, &test_policy, &result));
                EXPECT_TRUE(result.found_error);
            };

            /* Test: only sig scheme invalid */
            {
                struct s2n_security_policy test_policy = valid_policy;
                test_policy.signature_preferences = &invalid_sig_prefs;

                struct s2n_security_rule_result result = { 0 };
                EXPECT_OK(s2n_security_rule_validate_policy(
                        &test_rule, &test_policy, &result));
                EXPECT_TRUE(result.found_error);
            };

            /* Test: only cert sig scheme invalid */
            {
                struct s2n_security_policy test_policy = valid_policy;
                test_policy.certificate_signature_preferences = &invalid_sig_prefs;

                struct s2n_security_rule_result result = { 0 };
                EXPECT_OK(s2n_security_rule_validate_policy(
                        &test_rule, &test_policy, &result));
                EXPECT_TRUE(result.found_error);
            };

            /* Test: only curve invalid */
            {
                struct s2n_security_policy test_policy = valid_policy;
                test_policy.ecc_preferences = &invalid_ecc_prefs;

                struct s2n_security_rule_result result = { 0 };
                EXPECT_OK(s2n_security_rule_validate_policy(
                        &test_rule, &test_policy, &result));
                EXPECT_TRUE(result.found_error);
            };

            /* Test: only version invalid */
            {
                struct s2n_security_policy test_policy = valid_policy;
                test_policy.minimum_protocol_version = EXAMPLE_INVALID_VERSION;

                struct s2n_security_rule_result result = { 0 };
                EXPECT_OK(s2n_security_rule_validate_policy(
                        &test_rule, &test_policy, &result));
                EXPECT_TRUE(result.found_error);
            };
        };

        /* Test: skips certificate signature preferences if not present */
        {
            struct s2n_security_policy test_policy = valid_policy;
            test_policy.certificate_signature_preferences = NULL;

            struct s2n_security_rule_result result = { 0 };
            EXPECT_OK(s2n_security_rule_validate_policy(
                    &test_rule, &test_policy, &result));
            EXPECT_FALSE(result.found_error);
        };

        /* Test: writes output for errors
         *
         * These tests are little brittle because they include hard-coded outputs.
         * I think it's worthwhile to clearly verify the output.
         */
        {
            /* Test: Writes no output if output not enabled */
            {
                struct s2n_security_policy test_policy = valid_policy;
                test_policy.ecc_preferences = &invalid_ecc_prefs;

                DEFER_CLEANUP(struct s2n_security_rule_result result = { 0 },
                        s2n_security_rule_result_free);

                EXPECT_OK(s2n_security_rule_validate_policy(
                        &test_rule, &test_policy, &result));
                EXPECT_TRUE(result.found_error);

                size_t output_size = s2n_stuffer_data_available(&result.output);
                EXPECT_EQUAL(output_size, 0);
            };

            /* Test: Writes single line of output */
            {
                struct s2n_security_policy test_policy = valid_policy;
                test_policy.ecc_preferences = &invalid_ecc_prefs;
                const char expected_output[] =
                        "Test Rule: policy unnamed: curve: secp384r1 (#1)\n";

                DEFER_CLEANUP(struct s2n_security_rule_result result = { 0 },
                        s2n_security_rule_result_free);
                EXPECT_OK(s2n_security_rule_result_init_output(&result));

                EXPECT_OK(s2n_security_rule_validate_policy(
                        &test_rule, &test_policy, &result));
                EXPECT_TRUE(result.found_error);

                size_t output_size = s2n_stuffer_data_available(&result.output);
                EXPECT_EQUAL(output_size, strlen(expected_output));
                uint8_t *output_bytes = s2n_stuffer_raw_read(&result.output, output_size);
                EXPECT_NOT_NULL(output_bytes);
                EXPECT_BYTEARRAY_EQUAL(expected_output, output_bytes, output_size);
            };

            /* Test: Writes multiple lines of output for same field */
            {
                struct s2n_security_policy test_policy = valid_policy;
                test_policy.cipher_preferences = &invalid_cipher_prefs;
                const char expected_output[] =
                        "Test Rule: policy unnamed: cipher suite: TLS_AES_128_GCM_SHA256 (#1)\n"
                        "Test Rule: policy unnamed: cipher suite: TLS_CHACHA20_POLY1305_SHA256 (#3)\n";

                DEFER_CLEANUP(struct s2n_security_rule_result result = { 0 },
                        s2n_security_rule_result_free);
                EXPECT_OK(s2n_security_rule_result_init_output(&result));

                EXPECT_OK(s2n_security_rule_validate_policy(
                        &test_rule, &test_policy, &result));
                EXPECT_TRUE(result.found_error);

                size_t output_size = s2n_stuffer_data_available(&result.output);
                EXPECT_EQUAL(output_size, strlen(expected_output));
                uint8_t *output_bytes = s2n_stuffer_raw_read(&result.output, output_size);
                EXPECT_NOT_NULL(output_bytes);
                EXPECT_BYTEARRAY_EQUAL(expected_output, output_bytes, output_size);
            };

            /* Test: Writes multiple lines of output for different fields */
            {
                struct s2n_security_policy test_policy = valid_policy;
                test_policy.cipher_preferences = &invalid_cipher_prefs;
                test_policy.ecc_preferences = &invalid_ecc_prefs;
                const char expected_output[] =
                        "Test Rule: policy unnamed: cipher suite: TLS_AES_128_GCM_SHA256 (#1)\n"
                        "Test Rule: policy unnamed: cipher suite: TLS_CHACHA20_POLY1305_SHA256 (#3)\n"
                        "Test Rule: policy unnamed: curve: secp384r1 (#1)\n";

                DEFER_CLEANUP(struct s2n_security_rule_result result = { 0 },
                        s2n_security_rule_result_free);
                EXPECT_OK(s2n_security_rule_result_init_output(&result));

                EXPECT_OK(s2n_security_rule_validate_policy(
                        &test_rule, &test_policy, &result));
                EXPECT_TRUE(result.found_error);

                size_t output_size = s2n_stuffer_data_available(&result.output);
                EXPECT_EQUAL(output_size, strlen(expected_output));
                uint8_t *output_bytes = s2n_stuffer_raw_read(&result.output, output_size);
                EXPECT_NOT_NULL(output_bytes);
                EXPECT_BYTEARRAY_EQUAL(expected_output, output_bytes, output_size);
            };

            /* Writes correct name for versioned policy */
            {
                const char expected_prefix[] =
                        "Test Rule: policy test_all: ";
                const size_t expected_prefix_size = strlen(expected_prefix);

                DEFER_CLEANUP(struct s2n_security_rule_result result = { 0 },
                        s2n_security_rule_result_free);
                EXPECT_OK(s2n_security_rule_result_init_output(&result));

                EXPECT_OK(s2n_security_rule_validate_policy(
                        &test_rule, &security_policy_test_all, &result));
                EXPECT_TRUE(result.found_error);

                size_t output_size = s2n_stuffer_data_available(&result.output);
                EXPECT_TRUE(output_size > expected_prefix_size);
                uint8_t *output_bytes = s2n_stuffer_raw_read(&result.output, expected_prefix_size);
                EXPECT_NOT_NULL(output_bytes);
                EXPECT_BYTEARRAY_EQUAL(output_bytes, expected_prefix, expected_prefix_size);
            };
        };
    };

    /* Test s2n_security_policy_validate_security_rules
     * (and S2N_PERFECT_FORWARD_SECRECY-- we need to test with a real rule) */
    {
        struct s2n_cipher_suite *not_forward_secret_suite = &s2n_rsa_with_aes_128_gcm_sha256;
        const struct s2n_cipher_preferences not_forward_secret_prefs = {
            .suites = &not_forward_secret_suite,
            .count = 1,
        };

        struct s2n_cipher_suite *forward_secret_suites[] = {
            &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
            &s2n_tls13_aes_256_gcm_sha384,
        };
        const struct s2n_cipher_preferences forward_secret_prefs = {
            .suites = forward_secret_suites,
            .count = s2n_array_len(forward_secret_suites),
        };

        struct s2n_security_policy test_policy = valid_policy;

        /* Test: valid policy passes */
        {
            test_policy.rules[S2N_PERFECT_FORWARD_SECRECY] = true;
            test_policy.cipher_preferences = &forward_secret_prefs;

            struct s2n_security_rule_result result = { 0 };
            EXPECT_OK(s2n_security_policy_validate_security_rules(&test_policy, &result));
            EXPECT_FALSE(result.found_error);
        };

        /* Test: invalid policy fails */
        {
            test_policy.rules[S2N_PERFECT_FORWARD_SECRECY] = true;
            test_policy.cipher_preferences = &not_forward_secret_prefs;

            struct s2n_security_rule_result result = { 0 };
            EXPECT_OK(s2n_security_policy_validate_security_rules(&test_policy, &result));
            EXPECT_TRUE(result.found_error);
        };

        /* Test: valid policy without rule passes */
        {
            test_policy.rules[S2N_PERFECT_FORWARD_SECRECY] = false;
            test_policy.cipher_preferences = &forward_secret_prefs;

            struct s2n_security_rule_result result = { 0 };
            EXPECT_OK(s2n_security_policy_validate_security_rules(&test_policy, &result));
            EXPECT_FALSE(result.found_error);
        };

        /* Test: invalid policy without rule passes */
        {
            test_policy.rules[S2N_PERFECT_FORWARD_SECRECY] = false;
            test_policy.cipher_preferences = &not_forward_secret_prefs;

            struct s2n_security_rule_result result = { 0 };
            EXPECT_OK(s2n_security_policy_validate_security_rules(&test_policy, &result));
            EXPECT_FALSE(result.found_error);
        };
    };

    END_TEST();
}
