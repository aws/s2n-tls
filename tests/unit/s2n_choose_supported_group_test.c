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
#include "tls/extensions/s2n_client_supported_groups.h"
#include "tls/s2n_kem_preferences.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"

/* Include the C file directly to allow testing of static functions */
#include "tls/extensions/s2n_client_supported_groups.c"

/* This test checks the logic in the function s2n_choose_supported_group, which should select the highest
 * supported group or, if none are available, select NULL. */
int main()
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Tests with default KEM preferences (kem_preferences_null) */
    {
        /* If the lists of mutually supported groups are empty, chosen group should be set to null */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);
            EXPECT_EQUAL(kem_pref, &kem_preferences_null);

            for (size_t i = 0; i < ecc_pref->count; i++) {
                EXPECT_NULL(server_conn->kex_params.mutually_supported_curves[i]);
            }

            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                EXPECT_NULL(server_conn->kex_params.mutually_supported_kem_groups[i]);
            }

            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_params.kem);
            EXPECT_NULL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve);

            EXPECT_SUCCESS(s2n_choose_supported_group(server_conn));

            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_params.kem);
            EXPECT_NULL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve);
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* If the lists of mutually supported groups have one ECC match,
         * the chosen group should be set to the ECC match. */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);
            EXPECT_EQUAL(kem_pref, &kem_preferences_null);

            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_params.kem);
            EXPECT_NULL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve);

            for (size_t i = 0; i < ecc_pref->count; i++) {
                EXPECT_NULL(server_conn->kex_params.mutually_supported_curves[i]);
            }

            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                EXPECT_NULL(server_conn->kex_params.mutually_supported_kem_groups[i]);
            }

            server_conn->kex_params.mutually_supported_curves[1] = ecc_pref->ecc_curves[1];
            EXPECT_SUCCESS(s2n_choose_supported_group(server_conn));

            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_params.kem);
            EXPECT_EQUAL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[1]);
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* If the lists of mutually supported groups have several matches, the chosen group should be set to
         * the highest supported ECC. */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);
            EXPECT_EQUAL(kem_pref, &kem_preferences_null);

            for (size_t i = 0; i < ecc_pref->count; i++) {
                server_conn->kex_params.mutually_supported_curves[i] = ecc_pref->ecc_curves[i];
            }

            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                EXPECT_NULL(server_conn->kex_params.mutually_supported_kem_groups[i]);
            }

            EXPECT_SUCCESS(s2n_choose_supported_group(server_conn));

            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_params.kem);
            EXPECT_EQUAL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[0]);
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };
    };

    /* Test for PQ */
    {
        const struct s2n_kem_preferences test_kem_prefs = {
            .kem_count = 0,
            .kems = NULL,
            .tls13_kem_group_count = kem_preferences_all.tls13_kem_group_count,
            .tls13_kem_groups = kem_preferences_all.tls13_kem_groups,
        };

        const struct s2n_security_policy test_pq_security_policy = {
            .minimum_protocol_version = S2N_SSLv3,
            .cipher_preferences = &cipher_preferences_test_all_tls13,
            .kem_preferences = &test_kem_prefs,
            .signature_preferences = &s2n_signature_preferences_20200207,
            .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        /* If the server supports PQ, but the client didn't send any PQ IDs, mutually_supported_kem_groups will
         * not be populated, and the highest preference ECC should be chosen. */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->security_policy_override = &test_pq_security_policy;

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);
            EXPECT_EQUAL(kem_pref, &test_kem_prefs);

            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_params.kem);
            EXPECT_NULL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve);

            for (size_t i = 0; i < ecc_pref->count; i++) {
                server_conn->kex_params.mutually_supported_curves[i] = ecc_pref->ecc_curves[i];
            }

            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                EXPECT_NULL(server_conn->kex_params.mutually_supported_kem_groups[i]);
            }

            EXPECT_SUCCESS(s2n_choose_supported_group(server_conn));

            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_params.kem);
            EXPECT_EQUAL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[0]);
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* If server has multiple mutually supported KEM groups and ECC curves, the highest preferred KEM group
         * should be chosen. */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->security_policy_override = &test_pq_security_policy;

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);
            EXPECT_EQUAL(kem_pref, &test_kem_prefs);

            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_params.kem);
            EXPECT_NULL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve);

            for (size_t i = 0; i < ecc_pref->count; i++) {
                server_conn->kex_params.mutually_supported_curves[i] = ecc_pref->ecc_curves[i];
            }

            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                server_conn->kex_params.mutually_supported_kem_groups[i] = kem_pref->tls13_kem_groups[i];
            }

            EXPECT_SUCCESS(s2n_choose_supported_group(server_conn));

            const struct s2n_kem_group *kem_group = s2n_kem_preferences_get_highest_priority_group(kem_pref);
            if (s2n_pq_is_enabled()) {
                EXPECT_NOT_NULL(kem_group);
                EXPECT_EQUAL(server_conn->kex_params.server_kem_group_params.kem_group, kem_group);
                EXPECT_EQUAL(server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve, kem_group->curve);
                EXPECT_EQUAL(server_conn->kex_params.server_kem_group_params.kem_params.kem, kem_group->kem);
                EXPECT_NULL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve);
            } else {
                EXPECT_NULL(kem_group);
            }
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };
        /* If server has one mutually supported KEM group and multiple mutually supported ECC, the KEM
         * group should be chosen.
         * Need at least one available KEM to test fallback. */
        uint32_t available_groups = 0;
        EXPECT_OK(s2n_kem_preferences_groups_available(&kem_preferences_all, &available_groups));
        if (available_groups >= 1) {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->security_policy_override = &test_pq_security_policy;

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);
            EXPECT_EQUAL(kem_pref, &test_kem_prefs);

            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_params.kem);
            EXPECT_NULL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve);

            for (size_t i = 0; i < ecc_pref->count; i++) {
                server_conn->kex_params.mutually_supported_curves[i] = ecc_pref->ecc_curves[i];
            }

            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                EXPECT_NULL(server_conn->kex_params.mutually_supported_kem_groups[i]);
            }

            const struct s2n_kem_group *chosen_group = s2n_kem_preferences_get_highest_priority_group(kem_pref);
            EXPECT_NOT_NULL(chosen_group);
            server_conn->kex_params.mutually_supported_kem_groups[0] = chosen_group;
            EXPECT_SUCCESS(s2n_choose_supported_group(server_conn));

            EXPECT_EQUAL(server_conn->kex_params.server_kem_group_params.kem_group, chosen_group);
            EXPECT_EQUAL(server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve, chosen_group->curve);
            EXPECT_EQUAL(server_conn->kex_params.server_kem_group_params.kem_params.kem, chosen_group->kem);
            EXPECT_NULL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve);
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }
        /* If there are no mutually supported KEM groups or ECC curves, chosen group should be set to null */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->security_policy_override = &test_pq_security_policy;

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);
            EXPECT_EQUAL(kem_pref, &test_kem_prefs);

            for (size_t i = 0; i < ecc_pref->count; i++) {
                EXPECT_NULL(server_conn->kex_params.mutually_supported_curves[i]);
            }

            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                EXPECT_NULL(server_conn->kex_params.mutually_supported_kem_groups[i]);
            }

            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_params.kem);
            EXPECT_NULL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve);

            EXPECT_SUCCESS(s2n_choose_supported_group(server_conn));

            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->kex_params.server_kem_group_params.kem_params.kem);
            EXPECT_NULL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve);
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };
    };

    END_TEST();
}
