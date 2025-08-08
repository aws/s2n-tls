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

#include "policy/s2n_security_policy.h"

/* Checks whether cipher preference supports TLS 1.3 based on whether it is configured
 * with TLS 1.3 ciphers. Returns true or false.
 */
bool s2n_security_policy_supports_tls13(const struct s2n_security_policy *security_policy)
{
    if (security_policy == NULL) {
        return false;
    }

    for (uint8_t i = 0; security_policy_selection[i].version != NULL; i++) {
        if (security_policy_selection[i].security_policy == security_policy) {
            return security_policy_selection[i].supports_tls13 == 1;
        }
    }

    /* if cipher preference is not in the official list, compute the result */
    const struct s2n_cipher_preferences *cipher_preferences = security_policy->cipher_preferences;
    if (cipher_preferences == NULL) {
        return false;
    }

    for (size_t i = 0; i < cipher_preferences->count; i++) {
        if (cipher_preferences->suites[i]->minimum_required_tls_version >= S2N_TLS13) {
            return true;
        }
    }

    return false;
}

S2N_RESULT s2n_security_policy_validate_certificate_chain(
        const struct s2n_security_policy *security_policy,
        const struct s2n_cert_chain_and_key *cert_key_pair)
{
    RESULT_ENSURE_REF(security_policy);
    RESULT_ENSURE_REF(cert_key_pair);
    RESULT_ENSURE_REF(cert_key_pair->cert_chain);

    if (!security_policy->certificate_preferences_apply_locally) {
        return S2N_RESULT_OK;
    }

    struct s2n_cert *current = cert_key_pair->cert_chain->head;
    while (current != NULL) {
        RESULT_GUARD(s2n_security_policy_validate_cert_key(security_policy, &current->info,
                S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT));
        RESULT_GUARD(s2n_security_policy_validate_cert_signature(security_policy, &current->info,
                S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT));
        current = current->next;
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_security_policy_validate_cert_signature(const struct s2n_security_policy *security_policy,
        const struct s2n_cert_info *info, s2n_error error)
{
    RESULT_ENSURE_REF(info);
    RESULT_ENSURE_REF(security_policy);
    const struct s2n_signature_preferences *sig_preferences = security_policy->certificate_signature_preferences;

    if (sig_preferences != NULL) {
        for (size_t i = 0; i < sig_preferences->count; i++) {
            if (sig_preferences->signature_schemes[i]->libcrypto_nid == info->signature_nid) {
                return S2N_RESULT_OK;
            }
        }

        RESULT_BAIL(error);
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_security_policy_validate_cert_key(const struct s2n_security_policy *security_policy,
        const struct s2n_cert_info *info, s2n_error error)
{
    RESULT_ENSURE_REF(info);
    RESULT_ENSURE_REF(security_policy);
    const struct s2n_certificate_key_preferences *key_preferences = security_policy->certificate_key_preferences;

    if (key_preferences != NULL) {
        for (size_t i = 0; i < key_preferences->count; i++) {
            if (key_preferences->certificate_keys[i]->public_key_libcrypto_nid == info->public_key_nid
                    && key_preferences->certificate_keys[i]->bits == info->public_key_bits) {
                return S2N_RESULT_OK;
            }
        }
        RESULT_BAIL(error);
    }
    return S2N_RESULT_OK;
}
