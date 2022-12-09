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

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_connection *conn = NULL;
    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
    EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all"));

    uint8_t iana_value[2] = { 0 };

    /* Make sure the call fails before the connection has negotiated the cipher suite */
    EXPECT_FAILURE(s2n_connection_get_cipher_iana_value(conn, &iana_value[0], &iana_value[1]));

    const struct s2n_security_policy *security_policy = conn->security_policy_override;
    EXPECT_NOT_NULL(security_policy);

    const struct s2n_cipher_preferences *cipher_preferences = security_policy->cipher_preferences;
    EXPECT_NOT_NULL(cipher_preferences);

    /* Verify the cipher info functions work for every cipher suite */
    for (size_t cipher_idx = 0; cipher_idx < cipher_preferences->count; cipher_idx++) {
        struct s2n_cipher_suite *expected_cipher = cipher_preferences->suites[cipher_idx];
        conn->secure->cipher_suite = expected_cipher;

        EXPECT_STRING_EQUAL(s2n_connection_get_cipher(conn), expected_cipher->name);
        EXPECT_SUCCESS(s2n_connection_get_cipher_iana_value(conn, &iana_value[0], &iana_value[1]));
        EXPECT_EQUAL(memcmp(expected_cipher->iana_value, iana_value, sizeof(iana_value)), 0);
    }

    EXPECT_SUCCESS(s2n_connection_free(conn));

    END_TEST();
    return S2N_SUCCESS;
}
