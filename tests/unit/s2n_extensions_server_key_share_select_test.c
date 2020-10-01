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
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_server_key_share.h"
#include "tls/s2n_security_policies.h"

/* These tests check the server's logic when selecting a keyshare and supporting group. */
int main() {
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    /* If client and server have no mutually supported groups, abort the handshake without sending HRR. */
    {
        struct s2n_connection *server_conn = NULL;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);

        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_server_key_share_select(server_conn),
                S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
        EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* If client and server have no mutually supported groups but server received an ECC key share,
     * a Hello Retry Request flag is not set and the server ignores the mutually supported keyshare. */
    {
        struct s2n_connection *server_conn = NULL;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
        server_conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_pref->ecc_curves[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_conn->secure.client_ecc_evp_params[0]));

        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_server_key_share_select(server_conn),
                S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
        EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* If client has sent no keyshares, but server and client have a mutually supported EC curve,
     * send Hello Retry Request. */
    {
        struct s2n_connection *server_conn = NULL;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
        server_conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[1];
        EXPECT_NULL(server_conn->secure.mutually_supported_curves[0]);
        server_conn->secure.mutually_supported_curves[1] = ecc_pref->ecc_curves[1];
        for (size_t i = 0; i < ecc_pref->count; i++) {
            EXPECT_NULL(server_conn->secure.client_ecc_evp_params[i].evp_pkey);
            EXPECT_NULL(server_conn->secure.client_ecc_evp_params[i].negotiated_curve);
        }

        EXPECT_SUCCESS(s2n_extensions_server_key_share_select(server_conn));

        EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[1]);
        EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
        EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* When client and server mutually support curve 0 and curve 1, but client has only sent a keyshare for
     * curve 1, Hello Retry Request is not sent and server chooses curve 1. */
    {
        struct s2n_connection *server_conn = NULL;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        /* Server would have initially chosen curve[0] when processing the supported_groups extension */
        EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
        server_conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
        server_conn->secure.mutually_supported_curves[0] = ecc_pref->ecc_curves[0];
        server_conn->secure.mutually_supported_curves[1] = ecc_pref->ecc_curves[1];

        EXPECT_NULL(server_conn->secure.client_ecc_evp_params[0].evp_pkey);
        EXPECT_NULL(server_conn->secure.client_ecc_evp_params[0].negotiated_curve);
        server_conn->secure.client_ecc_evp_params[1].negotiated_curve = ecc_pref->ecc_curves[1];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_conn->secure.client_ecc_evp_params[1]));

        EXPECT_SUCCESS(s2n_extensions_server_key_share_select(server_conn));

        /* Server should have updated it's choice to curve[1] after taking received keyshares into account */
        EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[1]);
        EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
        EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn)); 
    }

    /* When client and server mutually support curve 0 and curve 1 and client has sent keyshares for both,
     * Hello Retry Request is not sent and server chooses curve 0. */
    {
        struct s2n_connection *server_conn = NULL;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        /* Server would have initially chosen curve[0] when processing the supported_groups extension */
        EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
        server_conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
        server_conn->secure.mutually_supported_curves[0] = ecc_pref->ecc_curves[0];
        server_conn->secure.mutually_supported_curves[1] = ecc_pref->ecc_curves[1];

        server_conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_pref->ecc_curves[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_conn->secure.client_ecc_evp_params[0]));
        server_conn->secure.client_ecc_evp_params[1].negotiated_curve = ecc_pref->ecc_curves[1];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_conn->secure.client_ecc_evp_params[1]));

        EXPECT_SUCCESS(s2n_extensions_server_key_share_select(server_conn));

        /* Server should still prefer curve[0] after taking received keyshares into account */
        EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[0]);
        EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
        EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

#if !defined(S2N_NO_PQ)
    {
        const struct s2n_kem_group *test_kem_groups[] = {
                &s2n_secp256r1_sike_p434_r2,
                &s2n_secp256r1_bike1_l1_r2,
                &s2n_secp256r1_kyber_512_r2
        };

        const struct s2n_kem_preferences test_kem_pref = {
                .kem_count = 0,
                .kems = NULL,
                .tls13_kem_group_count = s2n_array_len(test_kem_groups),
                .tls13_kem_groups = test_kem_groups,
        };

        const struct s2n_security_policy test_security_policy = {
                .minimum_protocol_version = S2N_SSLv3,
                .cipher_preferences = &cipher_preferences_test_all_tls13,
                .kem_preferences = &test_kem_pref,
                .signature_preferences = &s2n_signature_preferences_20200207,
                .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        /* If both server_curve and server_kem_group are set (erroneous behavior), we should
         * error and abort the handshake. */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->security_policy_override = &test_security_policy;
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);

            server_conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            server_conn->secure.server_kem_group_params.kem_group = kem_pref->tls13_kem_groups[0];

            EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_server_key_share_select(server_conn),
                    S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

            EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* If client and server have no mutually supported groups but server received a KEM group key share,
         * a Hello Retry Request flag is not set and the server ignores the keyshare. */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->security_policy_override = &test_security_policy;
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);

            /* Server would have not chosen any group when processing the supported_groups extension */
            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);

            /* Received an erroneous keyshare for kem group 0 */
            struct s2n_kem_group_params *client_params0 = &server_conn->secure.client_kem_group_params[0];
            const struct s2n_kem_group *kem_group0 = kem_pref->tls13_kem_groups[0];
            client_params0->kem_group = kem_group0;
            client_params0->kem_params.kem = kem_group0->kem;
            client_params0->ecc_params.negotiated_curve = kem_group0->curve;
            EXPECT_SUCCESS(s2n_alloc(&client_params0->kem_params.public_key, kem_group0->kem->public_key_length));
            EXPECT_SUCCESS(s2n_kem_generate_keypair(&client_params0->kem_params));
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params0->ecc_params));

            EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_server_key_share_select(server_conn),
                    S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

            /* Nothing selected, no HRR */
            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_group);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.kem_params.kem);
            EXPECT_NULL(server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->secure.chosen_client_kem_group_params);
            EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* If client has sent no keyshares but server and client mutually support KEM group 1,
         * select KEM group 1 and send Hello Retry Request. */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->security_policy_override = &test_security_policy;
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);

            /* Server would have initially chosen kem_group[1] when processing the supported_groups extension */
            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            struct s2n_kem_group_params *server_params = &server_conn->secure.server_kem_group_params;
            const struct s2n_kem_group *kem_group1 = kem_pref->tls13_kem_groups[1];
            server_params->kem_group = kem_group1;
            server_params->kem_params.kem = kem_group1->kem;
            server_params->ecc_params.negotiated_curve = kem_group1->curve;

            /* 0 is not supported, 1 is */
            EXPECT_NULL(server_conn->secure.mutually_supported_kem_groups[0]);
            server_conn->secure.mutually_supported_kem_groups[1] = kem_group1;

            /* No keyshares received */
            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].kem_group);
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].kem_params.kem);
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].kem_params.public_key.data);
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].ecc_params.negotiated_curve);
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].ecc_params.evp_pkey);
            }

            EXPECT_SUCCESS(s2n_extensions_server_key_share_select(server_conn));

            /* Server maintains its selection of KEM group 1, sends HRR */
            EXPECT_EQUAL(server_params->kem_group, kem_group1);
            EXPECT_EQUAL(server_params->kem_params.kem, kem_group1->kem);
            EXPECT_EQUAL(server_params->ecc_params.negotiated_curve, kem_group1->curve);
            EXPECT_NULL(server_conn->secure.chosen_client_kem_group_params);
            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* When client and server mutually support KEM groups 0 and 1, but client has only sent a keyshare for
         * KEM group 1, Hello Retry Request is not sent and server chooses group 1. */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->security_policy_override = &test_security_policy;
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);

            /* Server would have initially chosen kem_group[0] when processing the supported_groups extension */
            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            struct s2n_kem_group_params *server_params = &server_conn->secure.server_kem_group_params;
            const struct s2n_kem_group *kem_group0 = kem_pref->tls13_kem_groups[0];
            const struct s2n_kem_group *kem_group1 = kem_pref->tls13_kem_groups[1];
            server_params->kem_group = kem_group0;
            server_params->kem_params.kem = kem_group0->kem;
            server_params->ecc_params.negotiated_curve = kem_group0->curve;

            /* Both 0 and 1 supported */
            server_conn->secure.mutually_supported_kem_groups[0] = kem_group0;
            server_conn->secure.mutually_supported_kem_groups[1] = kem_group1;

            /* Received a keyshare for 1 only */
            EXPECT_NULL(server_conn->secure.client_kem_group_params[0].kem_group);
            struct s2n_kem_group_params *client_params1 = &server_conn->secure.client_kem_group_params[1];
            client_params1->kem_group = kem_group1;
            client_params1->kem_params.kem = kem_group1->kem;
            client_params1->ecc_params.negotiated_curve = kem_group1->curve;
            EXPECT_SUCCESS(s2n_alloc(&client_params1->kem_params.public_key, kem_group1->kem->public_key_length));
            EXPECT_SUCCESS(s2n_kem_generate_keypair(&client_params1->kem_params));
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params1->ecc_params));

            EXPECT_SUCCESS(s2n_extensions_server_key_share_select(server_conn));

            /* Server should have updated it's choice to kem_group[1] after taking received keyshares into account */
            EXPECT_EQUAL(server_params->kem_group, kem_group1);
            EXPECT_EQUAL(server_params->kem_params.kem, kem_group1->kem);
            EXPECT_EQUAL(server_params->ecc_params.negotiated_curve, kem_group1->curve);
            EXPECT_EQUAL(server_conn->secure.chosen_client_kem_group_params, client_params1);
            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* When client and server mutually support KEM groups 0,1,2 and client has sent keyshares for all,
         * Hello Retry Request is not sent and server chooses group 0. */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->security_policy_override = &test_security_policy;
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);

            /* Server would have initially chosen kem_group[0] when processing the supported_groups extension */
            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            struct s2n_kem_group_params *server_params = &server_conn->secure.server_kem_group_params;
            const struct s2n_kem_group *kem_group0 = kem_pref->tls13_kem_groups[0];
            server_params->kem_group = kem_group0;
            server_params->kem_params.kem = kem_group0->kem;
            server_params->ecc_params.negotiated_curve = kem_group0->curve;

            /* Support all KEM Groups; received key shares for all KEM groups */
            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                struct s2n_kem_group_params *client_params = &server_conn->secure.client_kem_group_params[i];
                const struct s2n_kem_group *kem_group = kem_pref->tls13_kem_groups[i];

                server_conn->secure.mutually_supported_kem_groups[i] = kem_group;

                client_params->kem_group = kem_group;
                client_params->kem_params.kem = kem_group->kem;
                client_params->ecc_params.negotiated_curve = kem_group->curve;
                EXPECT_SUCCESS(s2n_alloc(&client_params->kem_params.public_key, kem_group->kem->public_key_length));
                EXPECT_SUCCESS(s2n_kem_generate_keypair(&client_params->kem_params));
                EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params->ecc_params));
            }

            EXPECT_SUCCESS(s2n_extensions_server_key_share_select(server_conn));

            /* Server should still prefer kem_group[0] after taking received keyshares into account */
            EXPECT_EQUAL(server_params->kem_group, kem_group0);
            EXPECT_EQUAL(server_params->kem_params.kem, kem_group0->kem);
            EXPECT_EQUAL(server_params->ecc_params.negotiated_curve, kem_group0->curve);
            EXPECT_EQUAL(server_conn->secure.chosen_client_kem_group_params, &server_conn->secure.client_kem_group_params[0]);
            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* When client and server mutually support all KEM groups and all curves, but client sent no keyshares,
         * server should choose kem_group[0] and send HRR. */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->security_policy_override = &test_security_policy;
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);

            /* Server would have initially chosen kem_group[0] when processing the supported_groups extension */
            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            struct s2n_kem_group_params *server_params = &server_conn->secure.server_kem_group_params;
            const struct s2n_kem_group *kem_group0 = kem_pref->tls13_kem_groups[0];
            server_params->kem_group = kem_group0;
            server_params->kem_params.kem = kem_group0->kem;
            server_params->ecc_params.negotiated_curve = kem_group0->curve;

            /* Support all KEM groups and all curves */
            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                server_conn->secure.mutually_supported_kem_groups[i] = kem_pref->tls13_kem_groups[i];
            }
            for (size_t i = 0; i < ecc_pref->count; i++) {
                server_conn->secure.mutually_supported_curves[i] = ecc_pref->ecc_curves[i];
            }

            /* No keyshares received */
            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].kem_group);
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].kem_params.kem);
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].kem_params.public_key.data);
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].ecc_params.negotiated_curve);
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].ecc_params.evp_pkey);
            }

            EXPECT_SUCCESS(s2n_extensions_server_key_share_select(server_conn));

            /* Server should still prefer kem_group[0], and send HRR */
            EXPECT_EQUAL(server_params->kem_group, kem_group0);
            EXPECT_EQUAL(server_params->kem_params.kem, kem_group0->kem);
            EXPECT_EQUAL(server_params->ecc_params.negotiated_curve, kem_group0->curve);
            EXPECT_NULL(server_conn->secure.chosen_client_kem_group_params);
            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* When client and server mutually support all KEM groups and all curves, and client sent keyshares
         * for everything, server should choose kem_group[0] and not send HRR. */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->security_policy_override = &test_security_policy;
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);

            /* Server would have initially chosen kem_group[0] when processing the supported_groups extension */
            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            struct s2n_kem_group_params *server_params = &server_conn->secure.server_kem_group_params;
            const struct s2n_kem_group *kem_group0 = kem_pref->tls13_kem_groups[0];;
            server_params->kem_group = kem_group0;
            server_params->kem_params.kem = kem_group0->kem;
            server_params->ecc_params.negotiated_curve = kem_group0->curve;

            /* Support all KEM groups and curves; received keyshares for everything */
            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                struct s2n_kem_group_params *client_params = &server_conn->secure.client_kem_group_params[i];
                const struct s2n_kem_group *kem_group = kem_pref->tls13_kem_groups[i];

                server_conn->secure.mutually_supported_kem_groups[i] = kem_pref->tls13_kem_groups[i];

                client_params->kem_group = kem_group;
                client_params->kem_params.kem = kem_group->kem;
                client_params->ecc_params.negotiated_curve = kem_group->curve;
                EXPECT_SUCCESS(s2n_alloc(&client_params->kem_params.public_key, kem_group->kem->public_key_length));
                EXPECT_SUCCESS(s2n_kem_generate_keypair(&client_params->kem_params));
                EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params->ecc_params));
            }
            for (size_t i = 0; i < ecc_pref->count; i++) {
                struct s2n_ecc_evp_params *client_params = &server_conn->secure.client_ecc_evp_params[i];
                const struct s2n_ecc_named_curve *curve = ecc_pref->ecc_curves[i];

                server_conn->secure.mutually_supported_curves[i] = curve;

                client_params->negotiated_curve = curve;
                EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(client_params));
            }

            EXPECT_SUCCESS(s2n_extensions_server_key_share_select(server_conn));

            /* Server should still prefer kem_group[0], no HRR */
            EXPECT_EQUAL(server_params->kem_group, kem_group0);
            EXPECT_EQUAL(server_params->kem_params.kem, kem_group0->kem);
            EXPECT_EQUAL(server_params->ecc_params.negotiated_curve, kem_group0->curve);
            EXPECT_EQUAL(server_conn->secure.chosen_client_kem_group_params, &server_conn->secure.client_kem_group_params[0]);
            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* When client and server mutually support all KEM groups and all curves, but client sent keyshares
         * only for ECC, server should choose curves[0] and not send HRR. */
        {
            struct s2n_connection *server_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->security_policy_override = &test_security_policy;
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);

            /* Server would have initially chosen kem_group[0] when processing the supported_groups extension */
            EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
            struct s2n_kem_group_params *server_params = &server_conn->secure.server_kem_group_params;
            const struct s2n_kem_group *kem_group0 = kem_pref->tls13_kem_groups[0];;
            server_params->kem_group = kem_group0;
            server_params->kem_params.kem = kem_group0->kem;
            server_params->ecc_params.negotiated_curve = kem_group0->curve;

            /* Support all KEM groups, but no keyshares received */
            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                server_conn->secure.mutually_supported_kem_groups[i] = kem_pref->tls13_kem_groups[i];

                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].kem_group);
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].kem_params.kem);
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].kem_params.public_key.data);
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].ecc_params.negotiated_curve);
                EXPECT_NULL(server_conn->secure.client_kem_group_params[i].ecc_params.evp_pkey);
            }
            /* Support all curves, and all keyshares received */
            for (size_t i = 0; i < ecc_pref->count; i++) {
                struct s2n_ecc_evp_params *client_params = &server_conn->secure.client_ecc_evp_params[i];
                const struct s2n_ecc_named_curve *curve = ecc_pref->ecc_curves[i];

                server_conn->secure.mutually_supported_curves[i] = curve;

                client_params->negotiated_curve = curve;
                EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(client_params));
            }

            EXPECT_SUCCESS(s2n_extensions_server_key_share_select(server_conn));

            /* Server should update it's choice to curve[0], no HRR */
            EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[0]);
            EXPECT_NULL(server_params->kem_group);
            EXPECT_NULL(server_params->kem_params.kem);
            EXPECT_NULL(server_params->ecc_params.negotiated_curve);
            EXPECT_NULL(server_conn->secure.chosen_client_kem_group_params);
            EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }
    }
#endif

    END_TEST();
    return 0;
}
