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
#include "utils/s2n_blob.h"
#include "tls/extensions/s2n_client_supported_groups.h"
#include "tls/s2n_ecc_preferences.h"

int main(int argc, char **argv)
{
    struct s2n_connection *server_conn;
    struct s2n_blob iana_ids;
    struct s2n_stuffer out;

    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    /* These tests check how the server parses the supported groups sent by the client */
    {
        /* If the client sent a supported group that the server also supports, mutually_supported_groups
         * should contain the sent group.
         */
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(server_conn->config);
        const struct s2n_ecc_preferences *ecc_pref = server_conn->config->ecc_preferences;
        EXPECT_NOT_NULL(ecc_pref);
        
        uint8_t data[2] = {0};
        EXPECT_SUCCESS(s2n_blob_init(&iana_ids, data, sizeof(data)));
        EXPECT_SUCCESS(s2n_stuffer_init(&out, &iana_ids));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&out, ecc_pref->ecc_curves[0]->iana_id));

        for (int i = 0; i < ecc_pref->count; i++) {
            EXPECT_NULL(server_conn->secure.mutually_supported_groups[i]);
        }

        EXPECT_SUCCESS(s2n_parse_client_supported_groups_list(server_conn, &iana_ids, server_conn->secure.mutually_supported_groups));

        EXPECT_EQUAL(server_conn->secure.mutually_supported_groups[0], ecc_pref->ecc_curves[0]);
        EXPECT_NULL(server_conn->secure.mutually_supported_groups[1]);

        EXPECT_SUCCESS(s2n_connection_free(server_conn)); 
    }

    { 
        /* If the client sent no supported groups at all, mutually_supported_groups should contain
        * NULL values and no supported group should be chosen.
        */
        uint8_t data[2] = {0};
        EXPECT_SUCCESS(s2n_blob_init(&iana_ids, data, sizeof(data)));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(server_conn->config);
        const struct s2n_ecc_preferences *ecc_pref = server_conn->config->ecc_preferences;
        EXPECT_NOT_NULL(ecc_pref);

        EXPECT_SUCCESS(s2n_parse_client_supported_groups_list(server_conn, &iana_ids, server_conn->secure.mutually_supported_groups));

        for (int i = 0; i < ecc_pref->count; i++) {
            EXPECT_NULL(server_conn->secure.mutually_supported_groups[i]);
        }
        EXPECT_SUCCESS(s2n_connection_free(server_conn)); 
    }

    {
        /* If the client has sent one mutually supported group and several groups the server does not support,
        * mutually_supported_groups should contain only the group that the server supports.
        */
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(server_conn->config);
        const struct s2n_ecc_preferences *ecc_pref = server_conn->config->ecc_preferences;
        EXPECT_NOT_NULL(ecc_pref);

        uint8_t data[6] = {0};
        EXPECT_SUCCESS(s2n_blob_init(&iana_ids, data, sizeof(data)));
        EXPECT_SUCCESS(s2n_stuffer_init(&out, &iana_ids));
        /* 17 and 18 are unsupported ids */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&out, 17));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&out, 18));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&out, ecc_pref->ecc_curves[1]->iana_id));

        EXPECT_SUCCESS(s2n_parse_client_supported_groups_list(server_conn, &iana_ids, server_conn->secure.mutually_supported_groups));

        EXPECT_NULL(server_conn->secure.mutually_supported_groups[0]);
        EXPECT_EQUAL(server_conn->secure.mutually_supported_groups[1], ecc_pref->ecc_curves[1]);
        EXPECT_SUCCESS(s2n_connection_free(server_conn)); 
    }

    END_TEST();
    return 0;
}
