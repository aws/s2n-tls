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

#include "crypto/s2n_fips.h"
#include "s2n_testlib.h"
#include "utils/s2n_safety.h"

extern const struct s2n_ecc_named_curve s2n_unsupported_curve;

const struct s2n_ecc_named_curve *const ecc_pref_list_for_retry[] = {
    &s2n_unsupported_curve,
#if EVP_APIS_SUPPORTED
    &s2n_ecc_curve_x25519,
#endif
    &s2n_ecc_curve_secp256r1,
    &s2n_ecc_curve_secp384r1,
    &s2n_ecc_curve_secp521r1,
};
const struct s2n_ecc_preferences ecc_preferences_for_retry = {
    .count = s2n_array_len(ecc_pref_list_for_retry),
    .ecc_curves = ecc_pref_list_for_retry,
};

const struct s2n_security_policy security_policy_test_tls13_retry = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20190801,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20200207,
    .certificate_signature_preferences = &s2n_certificate_signature_preferences_20201110,
    .ecc_preferences = &ecc_preferences_for_retry,
};

/*
 * DEPRECATED: Do not use for new tests. Instead set an explicit security policy.
 * This method was used to preserve existing test behaviors when updating the default behavior
 * in https://github.com/aws/s2n-tls/pull/5549
 */
S2N_RESULT s2n_config_set_tls12_security_policy(struct s2n_config *config)
{
    if (s2n_is_in_fips_mode()) {
        RESULT_GUARD_POSIX(s2n_config_set_cipher_preferences(config, "20240502"));
    } else {
        RESULT_GUARD_POSIX(s2n_config_set_cipher_preferences(config, "20240501"));
    }
    return S2N_RESULT_OK;
}

/*
 * DEPRECATED: Do not use for new tests. Instead set an explicit security policy.
 * This method was used to preserve existing test behaviors when updating the default behavior
 * in https://github.com/aws/s2n-tls/pull/5549
 */
S2N_RESULT s2n_connection_set_tls12_security_policy(struct s2n_connection *connection)
{
    if (s2n_is_in_fips_mode()) {
        RESULT_GUARD_POSIX(s2n_connection_set_cipher_preferences(connection, "20240502"));
    } else {
        RESULT_GUARD_POSIX(s2n_connection_set_cipher_preferences(connection, "20240501"));
    }
    return S2N_RESULT_OK;
}
