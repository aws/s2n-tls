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

#define LEN_PREFIX 1

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* input values */
    const uint8_t protocol1[] = "protocol1";
    const size_t protocol1_len = strlen((const char *)protocol1);
    const uint8_t protocol2[] = "protocol abc 2";
    const size_t protocol2_len = strlen((const char *)protocol2);

    const uint8_t large_value[255] = { 0 };

    /* Test config append */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_EQUAL(config->application_protocols.size, 0);
        size_t prev_size = 0;

        /* should grow the blob with the provided value */
        EXPECT_SUCCESS(s2n_config_append_protocol_preference(config, protocol1, sizeof(protocol1)));
        EXPECT_EQUAL(config->application_protocols.size, LEN_PREFIX + sizeof(protocol1));
        prev_size = config->application_protocols.size;

        /* should grow the blob even more */
        EXPECT_SUCCESS(s2n_config_append_protocol_preference(config, protocol2, sizeof(protocol2)));
        EXPECT_EQUAL(config->application_protocols.size, prev_size + LEN_PREFIX + sizeof(protocol2));
        prev_size = config->application_protocols.size;

        /* should reallocate the blob with large values */
        EXPECT_SUCCESS(s2n_config_append_protocol_preference(config, large_value, sizeof(large_value)));
        EXPECT_EQUAL(config->application_protocols.size, prev_size + LEN_PREFIX + sizeof(large_value));
        prev_size = config->application_protocols.size;

        /* should not allow empty protocol values */
        EXPECT_FAILURE(s2n_config_append_protocol_preference(config, large_value, 0));
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
        EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, protocol1, sizeof(protocol1)));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, LEN_PREFIX + sizeof(protocol1));
        prev_size = conn->application_protocols_overridden.size;

        /* should grow the blob even more */
        EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, protocol2, sizeof(protocol2)));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, prev_size + LEN_PREFIX + sizeof(protocol2));
        prev_size = conn->application_protocols_overridden.size;

        /* should reallocate the blob with large values */
        EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, large_value, sizeof(large_value)));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, prev_size + LEN_PREFIX + sizeof(large_value));
        prev_size = conn->application_protocols_overridden.size;

        /* should not allow empty protocol values */
        EXPECT_FAILURE(s2n_connection_append_protocol_preference(conn, large_value, 0));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, prev_size);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    const char *protocols[] = { (const char *)protocol1, (const char *)protocol2 };
    const uint8_t protocols_count = s2n_array_len(protocols);

    char oversized_value[257] = { 0 };
    memset(&oversized_value, 1, 256);
    EXPECT_EQUAL(strlen(oversized_value), 256);
    const char *oversized[] = { oversized_value };
    const uint8_t oversized_count = s2n_array_len(oversized);

    /* Test config set */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_EQUAL(config->application_protocols.size, 0);

        /* should copy the preference list */
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
        EXPECT_EQUAL(config->application_protocols.size, LEN_PREFIX + protocol1_len + LEN_PREFIX + protocol2_len);

        /* should correctly free the old list list */
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, 1));
        EXPECT_EQUAL(config->application_protocols.size, LEN_PREFIX + protocol1_len);

        /* should clear the preference list */
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, NULL, protocols_count));
        EXPECT_EQUAL(config->application_protocols.size, 0);
        
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
        EXPECT_EQUAL(config->application_protocols.size, LEN_PREFIX + protocol1_len + LEN_PREFIX + protocol2_len);
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, 0));
        EXPECT_EQUAL(config->application_protocols.size, 0);

        /* should limit the length of the protocol value */
        EXPECT_FAILURE(s2n_config_set_protocol_preferences(config, oversized, oversized_count));
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
        EXPECT_EQUAL(conn->application_protocols_overridden.size, LEN_PREFIX + protocol1_len + LEN_PREFIX + protocol2_len);

        /* should correctly free the old list */
        EXPECT_SUCCESS(s2n_connection_set_protocol_preferences(conn, protocols, 1));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, LEN_PREFIX + protocol1_len);

        /* should clear the preference list */
        EXPECT_SUCCESS(s2n_connection_set_protocol_preferences(conn, NULL, protocols_count));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, 0);
        
        EXPECT_SUCCESS(s2n_connection_set_protocol_preferences(conn, protocols, protocols_count));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, LEN_PREFIX + protocol1_len + LEN_PREFIX + protocol2_len);
        EXPECT_SUCCESS(s2n_connection_set_protocol_preferences(conn, protocols, 0));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, 0);

        /* should limit the length of the protocol value */

        EXPECT_FAILURE(s2n_connection_set_protocol_preferences(conn, oversized, oversized_count));
        EXPECT_EQUAL(conn->application_protocols_overridden.size, 0);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
    return 0;
}
