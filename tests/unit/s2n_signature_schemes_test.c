/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_signature_scheme.h"
#include "tls/s2n_signature_algorithms.h"

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

    END_TEST();

    return 0;
}
