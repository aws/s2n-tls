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

int main(int argc, char **argv)
{
    struct s2n_connection *server_conn;

    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    /* These tests check the server's logic when selecting a keyshare and supporting group. */

    {
        /* If client and server have no mutually supported groups and no mutually supported
         * keyshares, a Hello Retry Request is not sent. 
         */
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);

        server_conn->client_protocol_version = S2N_TLS13;
        server_conn->server_protocol_version = S2N_TLS13;
        server_conn->actual_protocol_version = S2N_TLS13;

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        for (int i = 0; i < ecc_pref->count; i++) {
            EXPECT_NULL(server_conn->secure.client_ecc_evp_params[i].evp_pkey);
            EXPECT_NULL(server_conn->secure.client_ecc_evp_params[i].negotiated_curve);
            EXPECT_NULL(server_conn->secure.mutually_supported_groups[i]);
        }

        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_server_key_share_select(server_conn), S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_FALSE(s2n_is_hello_retry_message(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    {
        /* If client and server have no mutually supported groups but client and server have 
         * found mutually supported keyshares(erroneous behavior), a Hello Retry Request flag is not set and the server
         * ignores the mutually supported keyshare. 
         */ 
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);

        server_conn->client_protocol_version = S2N_TLS13;
        server_conn->server_protocol_version = S2N_TLS13;
        server_conn->actual_protocol_version = S2N_TLS13;

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        server_conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_pref->ecc_curves[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_conn->secure.client_ecc_evp_params[0]));

        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_server_key_share_select(server_conn), S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_FALSE(s2n_is_hello_retry_message(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn)); 
    }

    {
        /* If client has sent no keys but server and client have found a mutually supported group,
         * send Hello Retry Request. 
         */ 
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        server_conn->client_protocol_version = S2N_TLS13;
        server_conn->server_protocol_version = S2N_TLS13;
        server_conn->actual_protocol_version = S2N_TLS13;

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        server_conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
        server_conn->secure.mutually_supported_groups[0] = ecc_pref->ecc_curves[0];
        for (int i = 0; i < ecc_pref->count; i++) {
            EXPECT_NULL(server_conn->secure.client_ecc_evp_params[i].evp_pkey);
            EXPECT_NULL(server_conn->secure.client_ecc_evp_params[i].negotiated_curve);
        }
        EXPECT_SUCCESS(s2n_extensions_server_key_share_select(server_conn));

        EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[0]);

        /* Verify that the handshake type was updated correctly */
        EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    {
        /* When client and server mutually supported group 0 and group 1, but client has only sent a keyshare for
         * group 1, Hello Retry Request is not sent and server chooses group 1.
         */ 
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);

        server_conn->client_protocol_version = S2N_TLS13;
        server_conn->server_protocol_version = S2N_TLS13;
        server_conn->actual_protocol_version = S2N_TLS13;

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        server_conn->secure.mutually_supported_groups[0] = ecc_pref->ecc_curves[0];
        server_conn->secure.mutually_supported_groups[1] = ecc_pref->ecc_curves[1];

        EXPECT_NULL(server_conn->secure.client_ecc_evp_params[0].evp_pkey);
        EXPECT_NULL(server_conn->secure.client_ecc_evp_params[0].negotiated_curve);
        server_conn->secure.client_ecc_evp_params[1].negotiated_curve = ecc_pref->ecc_curves[1];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_conn->secure.client_ecc_evp_params[1]));

        EXPECT_SUCCESS(s2n_extensions_server_key_share_select(server_conn));

        EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[1]);
        EXPECT_FALSE(s2n_is_hello_retry_message(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn)); 
    }

    {
        /* When client and server mutually supported group 0 and client has sent a keyshare for group 0,
         * Hello Retry Request is not sent and server chooses group 0.
         */
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);

        server_conn->client_protocol_version = S2N_TLS13;
        server_conn->server_protocol_version = S2N_TLS13;
        server_conn->actual_protocol_version = S2N_TLS13;

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        server_conn->secure.mutually_supported_groups[0] = ecc_pref->ecc_curves[0];
        server_conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_pref->ecc_curves[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_conn->secure.client_ecc_evp_params[0]));

        EXPECT_SUCCESS(s2n_extensions_server_key_share_select(server_conn));

        EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[0]);
        EXPECT_FALSE(s2n_is_hello_retry_message(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn)); 
    } 

    END_TEST();
    return 0;
}
