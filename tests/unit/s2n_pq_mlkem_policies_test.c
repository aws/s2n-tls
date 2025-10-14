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

#include "crypto/s2n_pq.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"

static S2N_RESULT s2n_policy_has_cipher(const struct s2n_security_policy *security_policy, const struct s2n_cipher_suite *needle, bool *val)
{
    RESULT_ENSURE_REF(security_policy);
    RESULT_ENSURE_REF(security_policy->cipher_preferences);
    RESULT_ENSURE_REF(security_policy->cipher_preferences->suites);

    for (size_t i = 0; i < security_policy->cipher_preferences->count; i++) {
        const struct s2n_cipher_suite *hay = security_policy->cipher_preferences->suites[i];
        if (hay == needle) {
            *val = true;
            return S2N_RESULT_OK;
        }
    }

    *val = false;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_policy_has_kem(const struct s2n_security_policy *security_policy, const struct s2n_kem **kem_list, size_t kem_list_count, bool *val)
{
    RESULT_ENSURE_REF(security_policy);
    RESULT_ENSURE_REF(security_policy->kem_preferences);

    if (security_policy->kem_preferences->tls13_kem_groups == NULL || security_policy->kem_preferences->tls13_kem_group_count == 0) {
        *val = false;
        return S2N_RESULT_OK;
    }

    for (size_t i = 0; i < security_policy->kem_preferences->tls13_kem_group_count; i++) {
        const struct s2n_kem_group *supported_kem_group = security_policy->kem_preferences->tls13_kem_groups[i];
        RESULT_ENSURE_REF(supported_kem_group);
        for (int j = 0; j < kem_list_count; j++) {
            const struct s2n_kem *banned_kem = kem_list[j];
            RESULT_ENSURE_REF(banned_kem);
            if (supported_kem_group->kem == banned_kem) {
                *val = true;
                return S2N_RESULT_OK;
            }
        }
    }

    *val = false;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_policy_in_list(const char *policy_name, const char **exception_list, size_t list_count, bool *val)
{
    RESULT_ENSURE_REF(policy_name);

    for (size_t i = 0; i < list_count; i++) {
        const char *exception = exception_list[i];
        RESULT_ENSURE_REF(exception);

        if (strlen(policy_name) != strlen(exception)) {
            continue;
        }

        if (memcmp(policy_name, exception, strlen(policy_name)) == 0) {
            *val = true;
            return S2N_RESULT_OK;
        }
    }

    *val = false;
    return S2N_RESULT_OK;
}

/* List of all ML-KEM Parameter sizes */
const struct s2n_kem *mlkem_list[] = {
    &s2n_mlkem_768,
    &s2n_mlkem_1024
};

/* Ciphers that should not be present in TLS Policies that have ML-KEM */
const struct s2n_cipher_suite *legacy_cipher_suites[] = {
    &s2n_rsa_with_3des_ede_cbc_sha,
    &s2n_dhe_rsa_with_3des_ede_cbc_sha,
    &s2n_ecdhe_rsa_with_3des_ede_cbc_sha,
    &s2n_ecdhe_rsa_with_rc4_128_sha,
    &s2n_rsa_with_rc4_128_sha,
    &s2n_rsa_with_rc4_128_md5,
    &s2n_null_cipher_suite,
};

/* List of s2n TLS Security Policies that are allowed to have legacy TLS Ciphers and support ML-KEM */
const char *cipher_exceptions[] = {
    "CloudFront-Upstream-2025-PQ",
    "CloudFront-Upstream-TLS-1-0-2025-PQ",
    "CloudFront-Upstream-TLS-1-1-2025-PQ",
    "CloudFront-Upstream-TLS-1-2-2025-PQ",
    "CloudFront-Upstream-TLS-1-3-2025-PQ",
    "test_all",
};

/* List of s2n TLS Security Policies that are allowed to have a minimum TLS Version below TLS 1.2 and support ML-KEM */
const char *tls_version_exceptions[] = {
    "AWS-CRT-SDK-TLSv1.0-2025-PQ",
    "CloudFront-Upstream-2025-PQ",
    "CloudFront-Upstream-TLS-1-0-2025-PQ",
    "CloudFront-Upstream-TLS-1-1-2025-PQ",
    "test_all",
};

const size_t mlkem_list_size = s2n_array_len(mlkem_list);
const size_t cipher_exceptions_size = s2n_array_len(cipher_exceptions);
const size_t tls_version_exceptions_size = s2n_array_len(tls_version_exceptions);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Enforce minimum requirements on all security policies that support ML-KEM */
    for (size_t policy_index = 0; security_policy_selection[policy_index].version != NULL; policy_index++) {
        const struct s2n_security_policy_selection selection = security_policy_selection[policy_index];
        const char *policy_name = selection.version;
        const struct s2n_security_policy *security_policy = selection.security_policy;
        POSIX_ENSURE_REF(security_policy);

        bool has_mlkem = false;
        EXPECT_OK(s2n_policy_has_kem(security_policy, mlkem_list, mlkem_list_size, &has_mlkem));

        if (!has_mlkem) {
            continue;
        }

        /* ML-KEM requires TLS 1.3 in order to be negotiated. Ensure that Policies with ML-KEM also support TLS 1.3 */
        bool has_tls_13_cipher = false;
        for (size_t i = 0; i < security_policy->cipher_preferences->count; i++) {
            if (security_policy->cipher_preferences->suites[i]->minimum_required_tls_version == S2N_TLS13) {
                has_tls_13_cipher = true;
                break;
            }
        }
        EXPECT_TRUE(has_tls_13_cipher);

        /* Ensure all security policies that have ML-KEM support do not use previous draft wire-format
         * for Hybrid KeyShares with length prefixing. */
        const struct s2n_kem_preferences *kem_preferences = security_policy->kem_preferences;
        POSIX_ENSURE_REF(kem_preferences);
        EXPECT_FALSE(s2n_tls13_client_must_use_hybrid_kem_length_prefix(kem_preferences));

        /* All security policies that have ML-KEM should have TLS 1.2 as their minimum supported TLS Version */
        if (security_policy->minimum_protocol_version < S2N_TLS12) {
            bool has_exception = false;
            EXPECT_OK(s2n_policy_in_list(policy_name, tls_version_exceptions, tls_version_exceptions_size, &has_exception));

            if (!has_exception) {
                fprintf(stdout, "Security Policy: %s has ML-KEM and uses a legacy TLS Version: %d\n",
                        policy_name, security_policy->minimum_protocol_version);
                FAIL_MSG("ML-KEM policies should not contain legacy TLS Versions.");
            }
        }

        /* Policies that have ML-KEM should not have 3DES, RC4, or (abandoned/deprecated) draft TLS 1.2 Kyber support */
        for (int j = 0; j < s2n_array_len(legacy_cipher_suites); j++) {
            bool has_cipher = false;
            EXPECT_OK(s2n_policy_has_cipher(security_policy, legacy_cipher_suites[j], &has_cipher));

            if (has_cipher) {
                bool has_exception = false;
                EXPECT_OK(s2n_policy_in_list(policy_name, cipher_exceptions, cipher_exceptions_size, &has_exception));

                if (!has_exception) {
                    fprintf(stdout, "Security Policy: %s has ML-KEM and legacy cipher: %s\n",
                            policy_name, legacy_cipher_suites[j]->name);
                    FAIL_MSG("ML-KEM policies should not contain legacy ciphers.");
                }
            }
        }
    }

    /* Test configuring a PQ only policy on different libcryptos. */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        const char *policy = "test_pq_only";

        if (!s2n_is_tls13_fully_supported()) {
            EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_cipher_preferences(config, policy), S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
        } else if (!s2n_libcrypto_supports_mlkem()) {
            EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_cipher_preferences(config, policy), S2N_ERR_INVALID_SECURITY_POLICY);
        } else {
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, policy));
        }
    }

    /* Self-talk tests for PQ only policies on supported libcryptos. */
    if (s2n_is_tls13_fully_supported() && s2n_libcrypto_supports_mlkem()) {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        /* Test a PQ-only policy is able to negotiate. */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_pq_only"));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            /* Assert classical ECC is not negotiated & kem group is negotiated. */
            EXPECT_NULL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve);
            EXPECT_NOT_NULL(server_conn->kex_params.server_kem_group_params.kem_group);
        }

        /* Expect failure when a non-PQ client attempts to negotiate with a PQ-only server. */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "test_pq_only"));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_ECDHE_UNSUPPORTED_CURVE);
            /* Assert server negotiated_curve and kem_group are both NULL. */
            EXPECT_NULL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_group);
        }
    }

    END_TEST();
}
