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

#include <s2n.h>

#include "s2n_test.h"

#include "tls/s2n_config.h"
#include "tls/s2n_signature_scheme.h"
#include "tls/s2n_signature_algorithms.h"

/* needed for selection */
#include "tls/s2n_signature_scheme.c"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_config_set_signature_preferences */
    {
        struct s2n_config *config = s2n_config_new();

        EXPECT_SUCCESS(s2n_config_set_signature_preferences(config, "default"));
        EXPECT_EQUAL(config->signature_preferences, &s2n_signature_preferences_20140601);

        EXPECT_SUCCESS(s2n_config_set_signature_preferences(config, "dEfAUlT"));
        EXPECT_EQUAL(config->signature_preferences, &s2n_signature_preferences_20140601);

        EXPECT_SUCCESS(s2n_config_set_signature_preferences(config, "20200207"));
        EXPECT_EQUAL(config->signature_preferences, &s2n_signature_preferences_20200207);

        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_signature_preferences(config, "notathing"),
                S2N_ERR_INVALID_SIGNATURE_ALGORITHMS_PREFERENCES);

        s2n_config_free(config);
    }

    /* All signature preferences are valid */
    {
        for (int i = 0; selection[i].version != NULL; i++) {
            const struct s2n_signature_preferences *preferences = selection[i].preferences;
            for (int j = 0; j < preferences->count; j++) {
                const struct s2n_signature_scheme *scheme = preferences->signature_schemes[j];

                EXPECT_NOT_NULL(scheme);

                uint8_t max_version = scheme->maximum_protocol_version;
                uint8_t min_version = scheme->minimum_protocol_version;

                EXPECT_TRUE(max_version == S2N_UNKNOWN_PROTOCOL_VERSION || min_version <= max_version);

                /* If scheme will be used for tls1.3 */
                if (max_version == S2N_UNKNOWN_PROTOCOL_VERSION || max_version >= S2N_TLS13) {
                    EXPECT_NOT_EQUAL(scheme->hash_alg, S2N_HASH_SHA1);
                    EXPECT_NOT_EQUAL(scheme->sig_alg, S2N_SIGNATURE_RSA);
                    if (scheme->sig_alg == S2N_SIGNATURE_ECDSA) {
                        EXPECT_NOT_NULL(scheme->signature_curve);
                    }
                }

                /* If scheme will be used for pre-tls1.3 */
                if (min_version < S2N_TLS13) {
                    EXPECT_NULL(scheme->signature_curve);
                    EXPECT_NOT_EQUAL(scheme->sig_alg, S2N_SIGNATURE_RSA_PSS_PSS);
                }
            }
        }
    }

    END_TEST();

    return 0;
}
