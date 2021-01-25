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
#include "tls/s2n_connection.h"

#include <s2n.h>

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test config append */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_EQUAL(config->application_protocols.size, 0);
        size_t prev_size = 0;

        /* should grow the blob with the provided value */
        EXPECT_SUCCESS(s2n_config_append_protocol_preference(config, (const uint8_t *)"protocol1", 9));
        EXPECT_EQUAL(config->application_protocols.size, 1 /* len prefix */ + 9);
        prev_size = config->application_protocols.size;

        /* should grow the blob even more */
        EXPECT_SUCCESS(s2n_config_append_protocol_preference(config, (const uint8_t *)"protocol2", 9));
        EXPECT_EQUAL(config->application_protocols.size, prev_size + 1 /* len prefix */ + 9);
        prev_size = config->application_protocols.size;

        /* should allow null byte values */
        const uint8_t null_value[9] = { 0 };
        EXPECT_SUCCESS(s2n_config_append_protocol_preference(config, (const uint8_t *)null_value, 9));
        EXPECT_EQUAL(config->application_protocols.size, prev_size + 1 /* len prefix */ + 9);
        prev_size = config->application_protocols.size;

        /* should reallocate the blob */
        const uint8_t large_value[255] = { 0 };
        EXPECT_SUCCESS(s2n_config_append_protocol_preference(config, (const uint8_t *)large_value, 255));
        EXPECT_EQUAL(config->application_protocols.size, prev_size + 1 /* len prefix */ + 255);
        prev_size = config->application_protocols.size;

        /* should limit the length of the protocol value */
        const uint8_t oversized[256] = { 0 };
        EXPECT_FAILURE(s2n_config_append_protocol_preference(config, (const uint8_t *)oversized, 265));
        EXPECT_EQUAL(config->application_protocols.size, prev_size);

        EXPECT_SUCCESS(s2n_config_free(config));
    }

    /* Test connection append */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, 0);
        size_t prev_size = 0;

        /* should grow the blob with the provided value */
        EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, (const uint8_t *)"protocol1", 9));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, 1 /* len prefix */ + 9);
        prev_size = conn->application_protocols_overridden.size;

        /* should grow the blob even more */
        EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, (const uint8_t *)"protocol2", 9));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, prev_size + 1 /* len prefix */ + 9);
        prev_size = conn->application_protocols_overridden.size;

        /* should allow null byte values */
        const uint8_t null_value[9] = { 0 };
        EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, (const uint8_t *)null_value, 9));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, prev_size + 1 /* len prefix */ + 9);
        prev_size = conn->application_protocols_overridden.size;

        /* should reallocate the blob */
        const uint8_t large_value[255] = { 0 };
        EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, (const uint8_t *)large_value, 255));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, prev_size + 1 /* len prefix */ + 255);
        prev_size = conn->application_protocols_overridden.size;

        /* should limit the length of the protocol value */
        const uint8_t oversized[256] = { 0 };
        EXPECT_FAILURE(s2n_connection_append_protocol_preference(conn, (const uint8_t *)oversized, 265));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, prev_size);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    const char *protocols[] = { "protocol1", "protocol2", "protocol3" };
    const uint8_t protocols_count = s2n_array_len(protocols);

    /* Test config set */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_EQUAL(config->application_protocols.size, 0);

        /* should copy the preference list */
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
        EXPECT_EQUAL(config->application_protocols.size, (1 /* len prefix */ + 9) * protocols_count);

        /* should clear the preference list */
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, NULL, protocols_count));
        EXPECT_EQUAL(config->application_protocols.size, 0);
        
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
        EXPECT_EQUAL(config->application_protocols.size, (1 /* len prefix */ + 9) * protocols_count);
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, 0));
        EXPECT_EQUAL(config->application_protocols.size, 0);

        /* should limit the length of the protocol value */
        char oversized[257] = { 0 };
        memset(&oversized, 1, 256);
        EXPECT_EQUAL(strlen(oversized), 256);
        const char *oversized_p[] = { (const char *)&oversized };
        EXPECT_FAILURE(s2n_config_set_protocol_preferences(config, (const char * const *)oversized_p, 1));
        EXPECT_EQUAL(config->application_protocols.size, 0);

        EXPECT_SUCCESS(s2n_config_free(config));
    }

    /* Test connection set */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, 0);

        /* should copy the preference list */
        EXPECT_SUCCESS(s2n_connection_set_protocol_preferences(conn, protocols, protocols_count));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, (1 /* len prefix */ + 9) * protocols_count);

        /* should clear the preference list */
        EXPECT_SUCCESS(s2n_connection_set_protocol_preferences(conn, NULL, protocols_count));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, 0);
        
        EXPECT_SUCCESS(s2n_connection_set_protocol_preferences(conn, protocols, protocols_count));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, (1 /* len prefix */ + 9) * protocols_count);
        EXPECT_SUCCESS(s2n_connection_set_protocol_preferences(conn, protocols, 0));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, 0);

        /* should limit the length of the protocol value */
        char oversized[257] = { 0 };
        memset(&oversized, 1, 256);
        EXPECT_EQUAL(strlen(oversized), 256);
        const char *oversized_p[] = { (const char *)&oversized };
        EXPECT_FAILURE(s2n_connection_set_protocol_preferences(conn, (const char * const *)oversized_p, 1));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, 0);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
    return 0;
}
