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

#include "testlib/s2n_testlib.h"

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#include <s2n.h>

#include "crypto/s2n_fips.h"
#include "crypto/s2n_rsa_pss.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13());

    struct s2n_config *config = NULL;
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));

    struct s2n_connection *conn = NULL;
    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    uint8_t iana_value[2] = { 0, 0 };

    /* Make sure the call fails before the connection has negotiated the cipher suite */
    EXPECT_NULL(s2n_connection_get_cipher(conn));
    EXPECT_FAILURE(s2n_connection_get_cipher_iana_value(conn, &iana_value[0], &iana_value[1]));

    const struct s2n_security_policy *security_policy = config->security_policy;
    EXPECT_NOT_NULL(security_policy);

    const struct s2n_cipher_preferences *cipher_preferences = security_policy->cipher_preferences;
    EXPECT_NOT_NULL(cipher_preferences);

    /* Verify the cipher info functions work for every cipher suite */
    for (size_t cipher_idx = 0; cipher_idx < cipher_preferences->count; cipher_idx++) {
        struct s2n_cipher_suite *expected_cipher = cipher_preferences->suites[cipher_idx];
        conn->secure.cipher_suite = expected_cipher;

        EXPECT_STRING_EQUAL(s2n_connection_get_cipher(conn), expected_cipher->name);
        EXPECT_SUCCESS(s2n_connection_get_cipher_iana_value(conn, &iana_value[0], &iana_value[1]));
        EXPECT_EQUAL(memcmp(expected_cipher->iana_value, iana_value, sizeof(iana_value)), 0);
    }

    EXPECT_SUCCESS(s2n_connection_free(conn));
    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
    return 0;
}

