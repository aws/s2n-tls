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

#include "tls/s2n_signature_scheme.c"

#include "s2n_test.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test all signature schemes */
    size_t policy_i = 0;
    while (security_policy_selection[policy_i].version != NULL) {
        const struct s2n_signature_preferences *sig_prefs =
                security_policy_selection[policy_i].security_policy->signature_preferences;
        for (size_t sig_i = 0; sig_i < sig_prefs->count; sig_i++) {
            const struct s2n_signature_scheme *const sig_scheme = sig_prefs->signature_schemes[sig_i];

            EXPECT_NOT_EQUAL(sig_scheme->iana_value, 0);
            EXPECT_NOT_EQUAL(sig_scheme->hash_alg, S2N_HASH_NONE);
            EXPECT_NOT_EQUAL(sig_scheme->sig_alg, S2N_SIGNATURE_ANONYMOUS);
            EXPECT_NOT_EQUAL(sig_scheme->libcrypto_nid, 0);

            if (sig_scheme->sig_alg == S2N_SIGNATURE_ECDSA
                    && sig_scheme->minimum_protocol_version == S2N_TLS13) {
                EXPECT_NOT_NULL(sig_scheme->signature_curve);
            } else {
                EXPECT_NULL(sig_scheme->signature_curve);
            }
        }
        policy_i++;
    }

    END_TEST();
}
