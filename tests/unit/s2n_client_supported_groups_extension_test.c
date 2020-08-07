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

#include <stdint.h>

#include "tls/extensions/s2n_client_supported_groups.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"
#include "crypto/s2n_fips.h"

int main()
{
    BEGIN_TEST();

    /* Test s2n_extension_should_send_if_ecc_enabled */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        /* ecc extensions are required for the default config */
        EXPECT_TRUE(s2n_client_supported_groups_extension.should_send(conn));

        /* ecc extensions are NOT required for 20140601 */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "20140601"));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test send (with default KEM prefs = kem_preferences_null) */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        const struct s2n_kem_preferences *kem_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_pref));
        EXPECT_NOT_NULL(kem_pref);
        EXPECT_EQUAL(kem_pref, &kem_preferences_null);

        EXPECT_SUCCESS(s2n_client_supported_groups_extension.send(conn, &stuffer));

        uint16_t length;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &length));
        EXPECT_EQUAL(length, s2n_stuffer_data_available(&stuffer));
        EXPECT_EQUAL(length, ecc_pref->count * sizeof(uint16_t));

        uint16_t curve_id;
        for (int i = 0; i < ecc_pref->count; i++) {
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &curve_id));
            EXPECT_EQUAL(curve_id, ecc_pref->ecc_curves[i]->iana_id);
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

#if !defined(S2N_NO_PQ)
    /* Test send with KEM groups */
    {
        const struct s2n_kem_group *test_kem_groups[] = {
                &s2n_secp256r1_sike_p434_r2,
                &s2n_secp256r1_bike1_l1_r2,
        };

        const struct s2n_kem_preferences test_kem_prefs = {
                .kem_count = 0,
                .kems = NULL,
                .tls13_kem_group_count = s2n_array_len(test_kem_groups),
                .tls13_kem_groups = test_kem_groups,
        };

        const struct s2n_security_policy test_pq_security_policy = {
                .minimum_protocol_version = S2N_SSLv3,
                .cipher_preferences = &cipher_preferences_test_all_tls13,
                .kem_preferences = &test_kem_prefs,
                .signature_preferences = &s2n_signature_preferences_20200207,
                .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        if (!s2n_is_in_fips_mode()) {
            conn->security_policy_override = &test_pq_security_policy;
        }
        /* If in FIPS mode, the test will proceed using the default KEM preferences (kem_preferences_null) */

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        const struct s2n_kem_preferences *kem_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_pref));
        EXPECT_NOT_NULL(kem_pref);
        if (!s2n_is_in_fips_mode()) {
            EXPECT_EQUAL(kem_pref, &test_kem_prefs);
        } else {
            EXPECT_EQUAL(kem_pref, &kem_preferences_null);
        }

        EXPECT_SUCCESS(s2n_client_supported_groups_extension.send(conn, &stuffer));

        uint16_t length;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &length));
        EXPECT_EQUAL(length, s2n_stuffer_data_available(&stuffer));
        EXPECT_EQUAL(length, (ecc_pref->count * sizeof(uint16_t)) + (kem_pref->tls13_kem_group_count * sizeof(uint16_t)));

        uint16_t kem_id;
        for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &kem_id));
            EXPECT_EQUAL(kem_id, kem_pref->tls13_kem_groups[i]->iana_id);
        }

        uint16_t curve_id;
        for (int i = 0; i < ecc_pref->count; i++) {
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &curve_id));
            EXPECT_EQUAL(curve_id, ecc_pref->ecc_curves[i]->iana_id);
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }
#endif

    /* Test recv */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));

        EXPECT_SUCCESS(s2n_client_supported_groups_extension.send(conn, &stuffer));

        EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_SUCCESS(s2n_client_supported_groups_extension.recv(conn, &stuffer));
        EXPECT_EQUAL(conn->secure.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[0]);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test recv - no common curve */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));

        EXPECT_SUCCESS(s2n_client_supported_groups_extension.send(conn, &stuffer));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "null"));

        EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_SUCCESS(s2n_client_supported_groups_extension.recv(conn, &stuffer));
        EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test recv - malformed extension */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));

        EXPECT_SUCCESS(s2n_client_supported_groups_extension.send(conn, &stuffer));
        EXPECT_SUCCESS(s2n_stuffer_wipe_n(&stuffer, 1));

        EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_SUCCESS(s2n_client_supported_groups_extension.recv(conn, &stuffer));
        EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    {
        /* Test that unknown TLS_EXTENSION_SUPPORTED_GROUPS values are ignored */
        struct s2n_ecc_named_curve unsupported_curves[2] = {
                { .iana_id = 0x0, .libcrypto_nid = 0, .name = 0x0, .share_size = 0 },
                { .iana_id = 0xFF01, .libcrypto_nid = 0, .name = 0x0, .share_size = 0 },
        };
        int ec_curves_count = s2n_array_len(unsupported_curves);
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer supported_groups_extension;
        EXPECT_SUCCESS(s2n_stuffer_alloc(&supported_groups_extension, 2 + ec_curves_count * 2));
        GUARD(s2n_stuffer_write_uint16(&supported_groups_extension, ec_curves_count * 2));
        for (int i = 0; i < ec_curves_count; i++) {
            GUARD(s2n_stuffer_write_uint16(&supported_groups_extension, unsupported_curves[i].iana_id));
        }

        /* Force a bad value for the negotiated curve so we know extension was parsed and the curve was set to NULL */
        struct s2n_ecc_named_curve invalid_curve = { 0 };
        conn->secure.server_ecc_evp_params.negotiated_curve = &invalid_curve;
        EXPECT_SUCCESS(s2n_client_supported_groups_extension.recv(conn, &supported_groups_extension));
        EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);

        EXPECT_SUCCESS(s2n_stuffer_free(&supported_groups_extension));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
    return 0;
}
