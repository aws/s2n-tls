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
#include "tls/extensions/s2n_client_supported_groups.h"
#include "tls/s2n_ecc_preferences.h"

int main(int argc, char **argv) 
{
    struct s2n_connection *server_conn;

    BEGIN_TEST();
    /* This test checks the logic in the function s2n_choose_supported_group, which should select the highest
     * supported group or, if none are available, select NULL.
     */
    {
        /* If the list of mutually supported groups is empty, chosen curve should be set to null */
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_NOT_NULL(server_conn->config);
        const struct s2n_ecc_preferences *ecc_pref = server_conn->config->ecc_preferences;
        EXPECT_NOT_NULL(ecc_pref);
        for (int i = 0; i < ecc_pref->count; i++) {
            EXPECT_NULL(server_conn->secure.mutually_supported_groups[i]);
        }

        EXPECT_FAILURE_WITH_ERRNO(s2n_choose_supported_group(server_conn, server_conn->secure.mutually_supported_groups,
        &server_conn->secure.server_ecc_evp_params), S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    {
        /* If the list of mutually supported groups has one match, chosen curve should be set to that
         * match.
         */
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(server_conn->config);
        const struct s2n_ecc_preferences *ecc_pref = server_conn->config->ecc_preferences;
        EXPECT_NOT_NULL(ecc_pref);
        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
        server_conn->secure.mutually_supported_groups[1] = ecc_pref->ecc_curves[1];

        EXPECT_SUCCESS(s2n_choose_supported_group(server_conn, server_conn->secure.mutually_supported_groups,
            &server_conn->secure.server_ecc_evp_params));

        EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[1]);
        EXPECT_SUCCESS(s2n_connection_free(server_conn));

    }

    {
        /* If the list of mutually supported groups has several matches, chosen curve should be set to the first
         * match.
         */
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NULL(server_conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_NOT_NULL(server_conn->config);
        const struct s2n_ecc_preferences *ecc_pref = server_conn->config->ecc_preferences;
        EXPECT_NOT_NULL(ecc_pref);
        for (int i = 0; i < ecc_pref->count; i++) {
            server_conn->secure.mutually_supported_groups[i] = ecc_pref->ecc_curves[i];
        }

        EXPECT_SUCCESS(s2n_choose_supported_group(server_conn, server_conn->secure.mutually_supported_groups,
            &server_conn->secure.server_ecc_evp_params));

        EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[0]);
        EXPECT_SUCCESS(s2n_connection_free(server_conn));

    }

    END_TEST();
    return 0;

}
