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

#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/extensions/s2n_key_share.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls13.h"

#define S2N_IS_KEY_SHARE_LIST_EMPTY(preferred_key_shares) (preferred_key_shares & 1)
#define S2N_IS_KEY_SHARE_REQUESTED(preferred_key_shares, i) ((preferred_key_shares >> i) & 1)

int main(int argc, char **argv)
{
    BEGIN_TEST();
    struct s2n_connection *conn = NULL;
    struct s2n_config *config = NULL;

    /* Test error case for setting preferred keyshares prior to ecc_preferences being configured */
    {
        EXPECT_FAILURE(s2n_connection_set_keyshare_by_name_for_testing(conn, "secp256r1"));
    }
    /* Test sending empty keyshare */
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "none"));
        /* lsb is set */
        EXPECT_TRUE(S2N_IS_KEY_SHARE_LIST_EMPTY(conn->preferred_key_shares));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }
    /* Test sending single keyshares: p-256 */
    {
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        /* Explicity set default security_policy */
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20170210"));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);
        /* Test success for setting preferred keyshares bitmap for curve p-256 after ecc_preferences is configured
         * Default security policy has ecc_preferences in the following order: p-256, p-384 */
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "secp256r1"));
        /* lsb is not set */
        EXPECT_FALSE(S2N_IS_KEY_SHARE_LIST_EMPTY(conn->preferred_key_shares));
        /* Bitmap value for p-256 set is 00000010 */
        EXPECT_TRUE(S2N_IS_KEY_SHARE_REQUESTED(conn->preferred_key_shares, 1));
        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }
    /* Test success for setting multiple preferred keyshares: x25519 and p-384 */
    if (s2n_is_evp_apis_supported()) {
        EXPECT_SUCCESS(s2n_enable_tls13());
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        /* Explicity set default_tls13 security_policy */
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20190801"));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Default security policy for TLS1.3 has ecc_preferences in the following order: x25519, p-256, p-384.*/
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "x25519"));
        /* lsb is not set */
        EXPECT_FALSE(S2N_IS_KEY_SHARE_LIST_EMPTY(conn->preferred_key_shares));
        /* Bitmap value for x25519 set is 00000010 */
        EXPECT_TRUE(S2N_IS_KEY_SHARE_REQUESTED(conn->preferred_key_shares, 1));
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "secp384r1"));
        /* Bitmap value for p-384 and x25519 set is 00001010 */
        EXPECT_FALSE(S2N_IS_KEY_SHARE_REQUESTED(conn->preferred_key_shares, 2));
        EXPECT_TRUE(S2N_IS_KEY_SHARE_REQUESTED(conn->preferred_key_shares, 3));
        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_disable_tls13());
    }
    /* Test sending duplicate keyshares */
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "secp256r1"));
        /* lsb is not set */
        EXPECT_FALSE(S2N_IS_KEY_SHARE_LIST_EMPTY(conn->preferred_key_shares));
        /* Bitmap value for p-256 set is 00000010 */
        EXPECT_TRUE(S2N_IS_KEY_SHARE_REQUESTED(conn->preferred_key_shares, 1));
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "secp256r1"));
        EXPECT_TRUE(S2N_IS_KEY_SHARE_REQUESTED(conn->preferred_key_shares, 1));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }
    /* Test sending keyshares for all curves in default security policy->ecc_preferences: p-256, p-384*/
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_TRUE(!(conn->preferred_key_shares | 0));

        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "secp256r1"));
        /* lsb is not set */
        EXPECT_FALSE(S2N_IS_KEY_SHARE_LIST_EMPTY(conn->preferred_key_shares));
        /* Bitmap value for p-256 set is 00000010 */
        EXPECT_TRUE(S2N_IS_KEY_SHARE_REQUESTED(conn->preferred_key_shares, 1));
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(conn, "secp384r1"));
        /* Bitmap value for p-256 and p-384 set is 00000110 */
        EXPECT_TRUE(S2N_IS_KEY_SHARE_REQUESTED(conn->preferred_key_shares, 2));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }
    /* Test sending keyshare for curve not supported: Curve x448 */
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_TRUE(!(conn->preferred_key_shares | 0));
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_keyshare_by_name_for_testing(conn, "x448"),
                                  S2N_ERR_ECDHE_UNSUPPORTED_CURVE);
        EXPECT_TRUE(conn->preferred_key_shares == 0);
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }
    /* Test sending keyshare for curve not present in the ecc_preferences list but supported by s2n */
    if (s2n_is_evp_apis_supported()) {
        EXPECT_SUCCESS(s2n_enable_tls13());
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        /* Explicity set security_policy with ecc_preferences containing curves: p-256 and p-384 only. */
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20190802"));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        /* x25519 is not present in the security_policy "20190802"  */
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_keyshare_by_name_for_testing(conn, "x25519"),
                                  S2N_ERR_ECDHE_UNSUPPORTED_CURVE);
        EXPECT_TRUE(conn->preferred_key_shares == 0);
        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_disable_tls13());
    }

    END_TEST();
}
