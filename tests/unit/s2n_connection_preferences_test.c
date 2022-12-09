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

#include <stdlib.h>

#include "api/s2n.h"
#include "crypto/s2n_fips.h"
#include "s2n_test.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls13.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    const struct s2n_security_policy *default_security_policy, *tls13_security_policy, *fips_security_policy;
    EXPECT_SUCCESS(s2n_find_security_policy_from_version("default_tls13", &tls13_security_policy));
    EXPECT_SUCCESS(s2n_find_security_policy_from_version("default_fips", &fips_security_policy));
    EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &default_security_policy));

    /* Test default TLS1.2 */
    if (!s2n_is_in_fips_mode()) {
        struct s2n_connection *conn = NULL;
        const struct s2n_cipher_preferences *cipher_preferences = NULL;
        const struct s2n_security_policy *security_policy = NULL;
        const struct s2n_kem_preferences *kem_preferences = NULL;
        const struct s2n_signature_preferences *signature_preferences = NULL;
        const struct s2n_ecc_preferences *ecc_preferences = NULL;

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NULL(conn->security_policy_override);

        EXPECT_SUCCESS(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));
        EXPECT_EQUAL(cipher_preferences, default_security_policy->cipher_preferences);

        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, default_security_policy);

        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_preferences));
        EXPECT_EQUAL(kem_preferences, default_security_policy->kem_preferences);

        EXPECT_SUCCESS(s2n_connection_get_signature_preferences(conn, &signature_preferences));
        EXPECT_EQUAL(signature_preferences, default_security_policy->signature_preferences);

        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
        EXPECT_EQUAL(ecc_preferences, default_security_policy->ecc_preferences);

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "20170328"));
        EXPECT_NOT_NULL(conn->security_policy_override);

        cipher_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));
        EXPECT_EQUAL(cipher_preferences, security_policy_20170328.cipher_preferences);

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, &security_policy_20170328);

        kem_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_preferences));
        EXPECT_EQUAL(kem_preferences, security_policy_20170328.kem_preferences);

        signature_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_signature_preferences(conn, &signature_preferences));
        EXPECT_EQUAL(signature_preferences, security_policy_20170328.signature_preferences);

        ecc_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
        EXPECT_EQUAL(ecc_preferences, security_policy_20170328.ecc_preferences);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test TLS1.3 */
    {
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        struct s2n_connection *conn = NULL;
        const struct s2n_cipher_preferences *cipher_preferences = NULL;
        const struct s2n_security_policy *security_policy = NULL;
        const struct s2n_kem_preferences *kem_preferences = NULL;
        const struct s2n_signature_preferences *signature_preferences = NULL;
        const struct s2n_ecc_preferences *ecc_preferences = NULL;

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NULL(conn->security_policy_override);

        EXPECT_SUCCESS(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));
        EXPECT_EQUAL(cipher_preferences, tls13_security_policy->cipher_preferences);

        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, tls13_security_policy);

        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_preferences));
        EXPECT_EQUAL(kem_preferences, tls13_security_policy->kem_preferences);

        EXPECT_SUCCESS(s2n_connection_get_signature_preferences(conn, &signature_preferences));
        EXPECT_EQUAL(signature_preferences, tls13_security_policy->signature_preferences);

        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
        EXPECT_EQUAL(ecc_preferences, tls13_security_policy->ecc_preferences);

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all_tls13"));
        EXPECT_NOT_NULL(conn->security_policy_override);

        cipher_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));
        EXPECT_EQUAL(cipher_preferences, security_policy_test_all_tls13.cipher_preferences);

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, &security_policy_test_all_tls13);

        kem_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_preferences));
        EXPECT_EQUAL(kem_preferences, security_policy_test_all_tls13.kem_preferences);

        signature_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_signature_preferences(conn, &signature_preferences));
        EXPECT_EQUAL(signature_preferences, security_policy_test_all_tls13.signature_preferences);

        ecc_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
        EXPECT_EQUAL(ecc_preferences, security_policy_test_all_tls13.ecc_preferences);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };

    /* Test default fips */

    if (s2n_is_in_fips_mode()) {
        struct s2n_connection *conn = NULL;
        const struct s2n_cipher_preferences *cipher_preferences = NULL;
        const struct s2n_security_policy *security_policy = NULL;
        const struct s2n_kem_preferences *kem_preferences = NULL;
        const struct s2n_signature_preferences *signature_preferences = NULL;
        const struct s2n_ecc_preferences *ecc_preferences = NULL;

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NULL(conn->security_policy_override);

        EXPECT_SUCCESS(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));
        EXPECT_EQUAL(cipher_preferences, fips_security_policy->cipher_preferences);

        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, fips_security_policy);

        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_preferences));
        EXPECT_EQUAL(kem_preferences, fips_security_policy->kem_preferences);

        EXPECT_SUCCESS(s2n_connection_get_signature_preferences(conn, &signature_preferences));
        EXPECT_EQUAL(signature_preferences, fips_security_policy->signature_preferences);

        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
        EXPECT_EQUAL(ecc_preferences, fips_security_policy->ecc_preferences);

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all_fips"));
        EXPECT_NOT_NULL(conn->security_policy_override);

        cipher_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));
        EXPECT_EQUAL(cipher_preferences, security_policy_test_all_fips.cipher_preferences);

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, &security_policy_test_all_fips);

        kem_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_preferences));
        EXPECT_EQUAL(kem_preferences, security_policy_test_all_fips.kem_preferences);

        signature_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_signature_preferences(conn, &signature_preferences));
        EXPECT_EQUAL(signature_preferences, security_policy_test_all_fips.signature_preferences);

        ecc_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
        EXPECT_EQUAL(ecc_preferences, security_policy_test_all_fips.ecc_preferences);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test for NULL */
    {
        struct s2n_connection *conn = NULL;
        const struct s2n_cipher_preferences *cipher_preferences = NULL;
        const struct s2n_security_policy *security_policy = NULL;
        const struct s2n_kem_preferences *kem_preferences = NULL;
        const struct s2n_signature_preferences *signature_preferences = NULL;
        const struct s2n_ecc_preferences *ecc_preferences = NULL;

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NULL(conn->security_policy_override);
        EXPECT_FAILURE(s2n_connection_set_cipher_preferences(conn, NULL));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "null"));
        EXPECT_NOT_NULL(conn->security_policy_override);

        EXPECT_SUCCESS(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));
        EXPECT_EQUAL(cipher_preferences, &cipher_preferences_null);

        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, &security_policy_null);

        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_preferences));
        EXPECT_EQUAL(kem_preferences, &kem_preferences_null);

        EXPECT_SUCCESS(s2n_connection_get_signature_preferences(conn, &signature_preferences));
        EXPECT_EQUAL(signature_preferences, &s2n_signature_preferences_null);

        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
        EXPECT_EQUAL(ecc_preferences, &s2n_ecc_preferences_null);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test Error Case */
    {
        struct s2n_connection *conn = NULL;
        const struct s2n_cipher_preferences *cipher_preferences = NULL;
        const struct s2n_security_policy *security_policy = NULL;
        const struct s2n_kem_preferences *kem_preferences = NULL;
        const struct s2n_signature_preferences *signature_preferences = NULL;
        const struct s2n_ecc_preferences *ecc_preferences = NULL;

        EXPECT_FAILURE(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));
        EXPECT_FAILURE(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_FAILURE(s2n_connection_get_kem_preferences(conn, &kem_preferences));
        EXPECT_FAILURE(s2n_connection_get_signature_preferences(conn, &signature_preferences));
        EXPECT_FAILURE(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(conn->config->security_policy);
        EXPECT_NULL(conn->security_policy_override);

        conn->config->security_policy = NULL;

        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_cipher_preferences(conn, &cipher_preferences), S2N_ERR_INVALID_CIPHER_PREFERENCES);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_security_policy(conn, &security_policy), S2N_ERR_INVALID_SECURITY_POLICY);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_kem_preferences(conn, &kem_preferences), S2N_ERR_INVALID_KEM_PREFERENCES);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_signature_preferences(conn, &signature_preferences), S2N_ERR_INVALID_SIGNATURE_ALGORITHMS_PREFERENCES);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_ecc_preferences(conn, &ecc_preferences), S2N_ERR_INVALID_ECC_PREFERENCES);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* s2n_connection_get_curve */
    {
        struct s2n_connection *conn = NULL;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        const char *curve_name = NULL;
        char no_curve[] = { "NONE" };

        /* No curve negotiated yet */
        EXPECT_NOT_NULL(curve_name = s2n_connection_get_curve(conn));
        EXPECT_BYTEARRAY_EQUAL(curve_name, no_curve, strlen(no_curve));

        /* TLS1.3 always returns a curve */
        conn->actual_protocol_version = S2N_TLS13;
        conn->kex_params.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp256r1;
        EXPECT_NOT_NULL(curve_name = s2n_connection_get_curve(conn));
        EXPECT_BYTEARRAY_EQUAL(curve_name, s2n_ecc_curve_secp256r1.name, strlen(s2n_ecc_curve_secp256r1.name));

        /* TLS1.2 returns a curve if ECDHE cipher negotiated */
        conn->actual_protocol_version = S2N_TLS12;
        conn->secure->cipher_suite = &s2n_ecdhe_rsa_with_aes_128_cbc_sha256;
        conn->kex_params.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp256r1;
        EXPECT_NOT_NULL(curve_name = s2n_connection_get_curve(conn));
        EXPECT_BYTEARRAY_EQUAL(curve_name, s2n_ecc_curve_secp256r1.name, strlen(s2n_ecc_curve_secp256r1.name));

        /* TLS1.2 does not return a curve if ECDHE cipher was not negotiated */
        conn->actual_protocol_version = S2N_TLS12;
        conn->secure->cipher_suite = &s2n_rsa_with_aes_256_gcm_sha384;
        conn->kex_params.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp256r1;
        EXPECT_NOT_NULL(curve_name = s2n_connection_get_curve(conn));
        EXPECT_BYTEARRAY_EQUAL(curve_name, no_curve, strlen(no_curve));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    END_TEST();
}
