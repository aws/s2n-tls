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

#include "s2n_test.h"
#include <stdlib.h>
#include <s2n.h>

#include "crypto/s2n_fips.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_config.h"
#include "tls/s2n_ecc_preferences.h"
#include "tls/s2n_tls13.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const struct s2n_cipher_preferences *default_cipher_preferences, *tls13_cipher_preferences, *fips_cipher_preferences;
    EXPECT_SUCCESS(s2n_find_cipher_pref_from_version("default_tls13", &tls13_cipher_preferences));
    EXPECT_SUCCESS(s2n_find_cipher_pref_from_version("default_fips", &fips_cipher_preferences));
    EXPECT_SUCCESS(s2n_find_cipher_pref_from_version("default", &default_cipher_preferences));

    /* Test: s2n_config_new and tls13_default_config match */
    {
        struct s2n_config *config, *default_config;

        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_NOT_NULL(default_config = s2n_fetch_default_config());

        /* s2n_config_new() matches s2n_fetch_default_config() */
        EXPECT_EQUAL(default_config->cipher_preferences, config->cipher_preferences);
        EXPECT_EQUAL(default_config->signature_preferences, config->signature_preferences);
        EXPECT_EQUAL(default_config->client_cert_auth_type, config->client_cert_auth_type);

        /* Calling s2n_fetch_default_config() repeatedly returns the same object */
        EXPECT_EQUAL(default_config, s2n_fetch_default_config());

        /* TLS1.3 default does not match non-TLS1.3 default */
        EXPECT_SUCCESS(s2n_enable_tls13());
        EXPECT_NOT_EQUAL(default_config, s2n_fetch_default_config());
        EXPECT_SUCCESS(s2n_disable_tls13());

        EXPECT_SUCCESS(s2n_config_free(config));
    }

    /* Connections created with default configs */
    {
        /* For TLS1.2 */
        if (!s2n_is_in_fips_mode()) {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_EQUAL(conn->config, s2n_fetch_default_config());
            EXPECT_EQUAL(conn->config->cipher_preferences, default_cipher_preferences);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* For TLS1.3 */
        {
            EXPECT_SUCCESS(s2n_enable_tls13());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_EQUAL(conn->config, s2n_fetch_default_config());
            EXPECT_EQUAL(conn->config->cipher_preferences, tls13_cipher_preferences);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_disable_tls13());
        }

        /* For fips */
        if (s2n_is_in_fips_mode()) {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_EQUAL(conn->config, s2n_fetch_default_config());
            EXPECT_EQUAL(conn->config->cipher_preferences, fips_cipher_preferences);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_disable_tls13());
        }
    }

    /* Test for s2n_config_new() and tls 1.3 behavior */
    {
        if (!s2n_is_in_fips_mode()) {
            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_EQUAL(config->cipher_preferences, default_cipher_preferences);
            EXPECT_EQUAL(config->signature_preferences, &s2n_signature_preferences_20140601);
            EXPECT_EQUAL(config->ecc_preferences, &s2n_ecc_preferences_20140601);
            EXPECT_SUCCESS(s2n_config_free(config));

            EXPECT_SUCCESS(s2n_enable_tls13());
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_EQUAL(config->cipher_preferences, tls13_cipher_preferences);
            EXPECT_EQUAL(config->signature_preferences, &s2n_signature_preferences_20200207);
            EXPECT_EQUAL(config->ecc_preferences, &s2n_ecc_preferences_20200310);
            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_disable_tls13());
        }
    }

    END_TEST();
}
