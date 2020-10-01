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
#include "tls/s2n_tls13.h"

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
    {
        /* Define various PQ security policies to test different configurations */
        /* SIKE, BIKE*/
        const struct s2n_kem_group *test_kem_groups_sike_bike[] = {
                &s2n_secp256r1_sike_p434_r2,
                &s2n_secp256r1_bike1_l1_r2,
        };
        const struct s2n_kem_preferences test_kem_prefs_sike_bike = {
                .kem_count = 0,
                .kems = NULL,
                .tls13_kem_group_count = s2n_array_len(test_kem_groups_sike_bike),
                .tls13_kem_groups = test_kem_groups_sike_bike,
        };
        const struct s2n_security_policy test_pq_security_policy_sike_bike = {
                .minimum_protocol_version = S2N_SSLv3,
                .cipher_preferences = &cipher_preferences_test_all_tls13,
                .kem_preferences = &test_kem_prefs_sike_bike,
                .signature_preferences = &s2n_signature_preferences_20200207,
                .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        /* BIKE */
        const struct s2n_kem_group *test_kem_groups_bike[] = {
                &s2n_secp256r1_bike1_l1_r2,
        };
        const struct s2n_kem_preferences test_kem_prefs_bike = {
                .kem_count = 0,
                .kems = NULL,
                .tls13_kem_group_count = s2n_array_len(test_kem_groups_bike),
                .tls13_kem_groups = test_kem_groups_bike,
        };
        const struct s2n_security_policy test_pq_security_policy_bike = {
                .minimum_protocol_version = S2N_SSLv3,
                .cipher_preferences = &cipher_preferences_test_all_tls13,
                .kem_preferences = &test_kem_prefs_bike,
                .signature_preferences = &s2n_signature_preferences_20200207,
                .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        /* Kyber */
        const struct s2n_kem_group *test_kem_groups_kyber[] = {
                &s2n_secp256r1_kyber_512_r2,
        };
        const struct s2n_kem_preferences test_kem_prefs_kyber = {
                .kem_count = 0,
                .kems = NULL,
                .tls13_kem_group_count = s2n_array_len(test_kem_groups_kyber),
                .tls13_kem_groups = test_kem_groups_kyber,
        };
        const struct s2n_security_policy test_pq_security_policy_kyber = {
                .minimum_protocol_version = S2N_SSLv3,
                .cipher_preferences = &cipher_preferences_test_all_tls13,
                .kem_preferences = &test_kem_prefs_kyber,
                .signature_preferences = &s2n_signature_preferences_20200207,
                .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        /* BIKE, Kyber */
        const struct s2n_kem_group *test_kem_groups_bike_kyber[] = {
                &s2n_secp256r1_bike1_l1_r2,
                &s2n_secp256r1_kyber_512_r2,
        };
        const struct s2n_kem_preferences test_kem_prefs_bike_kyber = {
                .kem_count = 0,
                .kems = NULL,
                .tls13_kem_group_count = s2n_array_len(test_kem_groups_bike_kyber),
                .tls13_kem_groups = test_kem_groups_bike_kyber,
        };
        const struct s2n_security_policy test_pq_security_policy_bike_kyber = {
                .minimum_protocol_version = S2N_SSLv3,
                .cipher_preferences = &cipher_preferences_test_all_tls13,
                .kem_preferences = &test_kem_prefs_bike_kyber,
                .signature_preferences = &s2n_signature_preferences_20200207,
                .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        /* SIKE, Kyber */
        const struct s2n_kem_group *test_kem_groups_sike_kyber[] = {
                &s2n_secp256r1_sike_p434_r2,
                &s2n_secp256r1_kyber_512_r2,
        };
        const struct s2n_kem_preferences test_kem_prefs_sike_kyber = {
                .kem_count = 0,
                .kems = NULL,
                .tls13_kem_group_count = s2n_array_len(test_kem_groups_sike_kyber),
                .tls13_kem_groups = test_kem_groups_sike_kyber,
        };
        const struct s2n_security_policy test_pq_security_policy_sike_kyber = {
                .minimum_protocol_version = S2N_SSLv3,
                .cipher_preferences = &cipher_preferences_test_all_tls13,
                .kem_preferences = &test_kem_prefs_sike_kyber,
                .signature_preferences = &s2n_signature_preferences_20200207,
                .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        /* Test send with TLS 1.3 KEM groups */
        {
            EXPECT_SUCCESS(s2n_enable_tls13());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            DEFER_CLEANUP(struct s2n_stuffer stuffer = {0}, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            conn->security_policy_override = &test_pq_security_policy_sike_bike;

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);

            EXPECT_SUCCESS(s2n_client_supported_groups_extension.send(conn, &stuffer));

            uint16_t length;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &length));
            uint16_t expected_length = ecc_pref->count * sizeof(uint16_t);
            if (!s2n_is_in_fips_mode()) {
                expected_length += kem_pref->tls13_kem_group_count * sizeof(uint16_t);
            }
            EXPECT_EQUAL(length, s2n_stuffer_data_available(&stuffer));
            EXPECT_EQUAL(length, expected_length);

            if (!s2n_is_in_fips_mode()) {
                uint16_t kem_id;
                for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                    EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &kem_id));
                    EXPECT_EQUAL(kem_id, kem_pref->tls13_kem_groups[i]->iana_id);
                }
            }

            uint16_t curve_id;
            for (int i = 0; i < ecc_pref->count; i++) {
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &curve_id));
                EXPECT_EQUAL(curve_id, ecc_pref->ecc_curves[i]->iana_id);
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_disable_tls13());
        }
        /* Test that send does not send KEM group IDs for versions != TLS 1.3 */
        {
            EXPECT_FALSE(s2n_is_tls13_enabled());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            DEFER_CLEANUP(struct s2n_stuffer stuffer = {0}, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            conn->security_policy_override = &test_pq_security_policy_sike_bike;

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);

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

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
        /* Test recv - in each case, the security policy overrides allow for a successful PQ handshake */
        {
#define NUM_PQ_TEST_POLICY_OVERRIDES 4
            /* Security policy overrides: {client_policy, server_policy} */
            const struct s2n_security_policy *test_policy_overrides[NUM_PQ_TEST_POLICY_OVERRIDES][2] = {
                    /* Client sends SIKE, BIKE; server supports SIKE, BIKE */
                    {&test_pq_security_policy_sike_bike, &test_pq_security_policy_sike_bike},
                    /* Client sends SIKE, BIKE; server supports BIKE */
                    {&test_pq_security_policy_sike_bike, &test_pq_security_policy_bike},
                    /* Client sends BIKE; server supports SIKE, BIKE */
                    {&test_pq_security_policy_bike, &test_pq_security_policy_sike_bike},
                    /* Client sends SIKE, Kyber; server supports BIKE, Kyber */
                    {&test_pq_security_policy_sike_kyber, &test_pq_security_policy_bike_kyber},
            };
            /* Expected KEM group to be negotiated - corresponds to test_policy_overrides array */
            const struct s2n_kem_group *expected_negotiated_kem_group[NUM_PQ_TEST_POLICY_OVERRIDES] = {
                    &s2n_secp256r1_sike_p434_r2,
                    &s2n_secp256r1_bike1_l1_r2,
                    &s2n_secp256r1_bike1_l1_r2,
                    &s2n_secp256r1_kyber_512_r2,
            };

            for (size_t i = 0; i < NUM_PQ_TEST_POLICY_OVERRIDES; i++) {
                EXPECT_SUCCESS(s2n_enable_tls13());
                struct s2n_connection *client_conn;
                EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
                client_conn->security_policy_override = test_policy_overrides[i][0];

                struct s2n_connection *server_conn;
                EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_CLIENT));
                server_conn->security_policy_override = test_policy_overrides[i][1];

                DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

                const struct s2n_ecc_preferences *server_ecc_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &server_ecc_pref));
                EXPECT_NOT_NULL(server_ecc_pref);

                const struct s2n_kem_preferences *server_kem_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &server_kem_pref));
                EXPECT_NOT_NULL(server_kem_pref);

                EXPECT_SUCCESS(s2n_client_supported_groups_extension.send(client_conn, &stuffer));

                EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_params.kem);

                EXPECT_SUCCESS(s2n_client_supported_groups_extension.recv(server_conn, &stuffer));

                /* If in FIPS mode, s2n_client_supported_groups_extension.send will not have sent PQ IDs */
                if (s2n_is_in_fips_mode()) {
                    EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, server_ecc_pref->ecc_curves[0]);
                    EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
                    EXPECT_NULL(server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
                    EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_params.kem);

                    for (size_t j = 0; j < server_kem_pref->tls13_kem_group_count; j++) {
                        EXPECT_NULL(server_conn->secure.mutually_supported_kem_groups[j]);
                    }
                } else {
                    EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
                    EXPECT_EQUAL(server_conn->secure.server_kem_group_params.kem_group, expected_negotiated_kem_group[i]);
                    EXPECT_EQUAL(server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve, expected_negotiated_kem_group[i]->curve);
                    EXPECT_EQUAL(server_conn->secure.server_kem_group_params.kem_params.kem, expected_negotiated_kem_group[i]->kem);
                }

                EXPECT_SUCCESS(s2n_connection_free(client_conn));
                EXPECT_SUCCESS(s2n_connection_free(server_conn));
                EXPECT_SUCCESS(s2n_disable_tls13());
            }
        }
        /* Test recv - in each case, the security policy overrides do not allow for a successful PQ handshake,
         * so ECC should be chosen */
        {
#define NUM_MISMATCH_PQ_TEST_POLICY_OVERRIDES 5
            /* Security policy overrides: {client_policy, server_policy} */
            const struct s2n_security_policy *test_policy_overrides[NUM_MISMATCH_PQ_TEST_POLICY_OVERRIDES][2] = {
                    /* Client sends SIKE, BIKE; server supports only Kyber */
                    {&test_pq_security_policy_sike_bike, &test_pq_security_policy_kyber},
                    /* Client sends Kyber; server supports SIKE, BIKE */
                    {&test_pq_security_policy_kyber, &test_pq_security_policy_sike_bike},
                    /* Client sends SIKE, BIKE; server supports only ECC */
                    {&test_pq_security_policy_sike_bike, NULL},
                    /* Client sends only ECC ; server supports ECC and SIKE, BIKE */
                    {NULL, &test_pq_security_policy_sike_bike},
                    /* Client sends only ECC; server supports only ECC */
                    {NULL, NULL}
            };

            for (size_t i = 0; i < NUM_MISMATCH_PQ_TEST_POLICY_OVERRIDES; i++) {
                EXPECT_SUCCESS(s2n_enable_tls13());
                struct s2n_connection *client_conn;
                EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
                client_conn->security_policy_override = test_policy_overrides[i][0];

                struct s2n_connection *server_conn;
                EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_CLIENT));
                server_conn->security_policy_override = test_policy_overrides[i][1];

                const struct s2n_ecc_preferences *server_ecc_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &server_ecc_pref));
                EXPECT_NOT_NULL(server_ecc_pref);

                DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

                EXPECT_SUCCESS(s2n_client_supported_groups_extension.send(client_conn, &stuffer));

                EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_params.kem);

                EXPECT_SUCCESS(s2n_client_supported_groups_extension.recv(server_conn, &stuffer));

                EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, server_ecc_pref->ecc_curves[0]);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_params.kem);

                EXPECT_SUCCESS(s2n_connection_free(client_conn));
                EXPECT_SUCCESS(s2n_connection_free(server_conn));
                EXPECT_SUCCESS(s2n_disable_tls13());
            }
        }

        /* Test recv - client sends exclusively unrecognized groups */
        {
            EXPECT_SUCCESS(s2n_enable_tls13());

            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_CLIENT));
            server_conn->security_policy_override = &test_pq_security_policy_sike_bike;

            /* Manually craft a supported_groups extension with bogus IDs */
            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            struct s2n_stuffer_reservation group_list_len = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &group_list_len));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, 100));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, 101));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, 102));
            GUARD(s2n_stuffer_write_vector_size(&group_list_len));

            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_params.kem);

            EXPECT_SUCCESS(s2n_client_supported_groups_extension.recv(server_conn, &stuffer));

            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_params.kem);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_disable_tls13());
        }

        /* Test recv - server doesn't recognize PQ group IDs when TLS 1.3 is disabled */
        {
            EXPECT_SUCCESS(s2n_disable_tls13());
            EXPECT_FALSE(s2n_is_tls13_enabled());
            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            client_conn->security_policy_override = &test_pq_security_policy_sike_bike;

            const struct s2n_ecc_preferences *client_ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(client_conn, &client_ecc_pref));
            EXPECT_NOT_NULL(client_ecc_pref);

            const struct s2n_kem_preferences *client_kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(client_conn, &client_kem_pref));
            EXPECT_NOT_NULL(client_kem_pref);

            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_CLIENT));
            server_conn->security_policy_override = &test_pq_security_policy_sike_bike;

            /* Manually craft a supported_groups extension with one PQ ID and one ECC ID, because
             * s2n_client_supported_groups_extension.send will ignore PQ IDs when TLS 1.3 is disabled */
            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            struct s2n_stuffer_reservation group_list_len = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &group_list_len));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, client_kem_pref->tls13_kem_groups[0]->iana_id));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, client_ecc_pref->ecc_curves[0]->iana_id));
            GUARD(s2n_stuffer_write_vector_size(&group_list_len));

            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_params.kem);

            EXPECT_SUCCESS(s2n_client_supported_groups_extension.recv(server_conn, &stuffer));

            EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, client_ecc_pref->ecc_curves[0]);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_params.kem);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Test recv - server doesn't recognize PQ group IDs when FIPS is enabled */
        {
            if (s2n_is_in_fips_mode()) {
                EXPECT_SUCCESS(s2n_enable_tls13());
                struct s2n_connection *client_conn;
                EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
                client_conn->security_policy_override = &test_pq_security_policy_sike_bike;

                const struct s2n_ecc_preferences *client_ecc_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(client_conn, &client_ecc_pref));
                EXPECT_NOT_NULL(client_ecc_pref);

                const struct s2n_kem_preferences *client_kem_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_kem_preferences(client_conn, &client_kem_pref));
                EXPECT_NOT_NULL(client_kem_pref);

                struct s2n_connection *server_conn;
                EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_CLIENT));
                server_conn->security_policy_override = &test_pq_security_policy_sike_bike;

                /* Manually craft a supported_groups extension with one PQ ID and one ECC ID, because
                 * s2n_client_supported_groups_extension.send will ignore PQ IDs when FIPS is enabled */
                DEFER_CLEANUP(struct s2n_stuffer stuffer = {0}, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
                struct s2n_stuffer_reservation group_list_len = {0};
                EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &group_list_len));
                EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, client_kem_pref->tls13_kem_groups[0]->iana_id));
                EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, client_ecc_pref->ecc_curves[0]->iana_id));
                GUARD(s2n_stuffer_write_vector_size(&group_list_len));

                EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_params.kem);

                EXPECT_SUCCESS(s2n_client_supported_groups_extension.recv(server_conn, &stuffer));

                EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve,client_ecc_pref->ecc_curves[0]);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
                EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_params.kem);

                EXPECT_SUCCESS(s2n_connection_free(client_conn));
                EXPECT_SUCCESS(s2n_connection_free(server_conn));
                EXPECT_SUCCESS(s2n_disable_tls13());
            }
        }
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
        EXPECT_NOT_NULL(ecc_pref);

        EXPECT_SUCCESS(s2n_client_supported_groups_extension.send(conn, &stuffer));

        EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_SUCCESS(s2n_client_supported_groups_extension.recv(conn, &stuffer));
        EXPECT_EQUAL(conn->secure.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[0]);
        EXPECT_NULL(conn->secure.server_kem_group_params.kem_group);
        EXPECT_NULL(conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        EXPECT_NULL(conn->secure.server_kem_group_params.kem_params.kem);

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
        EXPECT_NOT_NULL(ecc_pref);

        EXPECT_SUCCESS(s2n_client_supported_groups_extension.send(conn, &stuffer));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "null"));

        EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_SUCCESS(s2n_client_supported_groups_extension.recv(conn, &stuffer));
        EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_NULL(conn->secure.server_kem_group_params.kem_group);
        EXPECT_NULL(conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        EXPECT_NULL(conn->secure.server_kem_group_params.kem_params.kem);

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
        EXPECT_NOT_NULL(ecc_pref);

        EXPECT_SUCCESS(s2n_client_supported_groups_extension.send(conn, &stuffer));
        EXPECT_SUCCESS(s2n_stuffer_wipe_n(&stuffer, 1));

        EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_SUCCESS(s2n_client_supported_groups_extension.recv(conn, &stuffer));
        EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_NULL(conn->secure.server_kem_group_params.kem_group);
        EXPECT_NULL(conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        EXPECT_NULL(conn->secure.server_kem_group_params.kem_params.kem);

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
        EXPECT_NULL(conn->secure.server_kem_group_params.kem_group);
        EXPECT_NULL(conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        EXPECT_NULL(conn->secure.server_kem_group_params.kem_params.kem);

        EXPECT_SUCCESS(s2n_stuffer_free(&supported_groups_extension));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
    return 0;
}
