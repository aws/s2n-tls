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

#include "tls/s2n_protocol_preferences.h"

#include "api/s2n.h"
#include "s2n_test.h"
#include "tls/extensions/s2n_client_alpn.h"
#include "tls/s2n_connection.h"

#define LEN_PREFIX 1

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* input values */
    const uint8_t protocol1[] = "protocol1";
    const size_t protocol1_len = strlen((const char *) protocol1);
    const uint8_t protocol2[] = "protocol abc 2";
    const size_t protocol2_len = strlen((const char *) protocol2);

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
    };

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
    };

    const char *protocols[] = { (const char *) protocol1, (const char *) protocol2 };
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
    };

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
    };

    /* Test s2n_protocol_preferences_read */
    {
        /* Safety checks */
        {
            struct s2n_stuffer stuffer = { 0 };
            struct s2n_blob blob = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_protocol_preferences_read(NULL, &blob), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_protocol_preferences_read(&stuffer, NULL), S2N_ERR_NULL);
        };

        /* Fail to read zero-length protocol */
        {
            struct s2n_stuffer input = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, 0));

            struct s2n_blob result = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_protocol_preferences_read(&input, &result), S2N_ERR_SAFETY);
            EXPECT_EQUAL(result.size, 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&input));
        };

        /* Read valid value */
        {
            struct s2n_stuffer input = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, sizeof(protocol1)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, protocol1, sizeof(protocol1)));

            struct s2n_blob result = { 0 };
            EXPECT_OK(s2n_protocol_preferences_read(&input, &result));
            EXPECT_EQUAL(result.size, sizeof(protocol1));
            EXPECT_BYTEARRAY_EQUAL(result.data, protocol1, sizeof(protocol1));

            EXPECT_SUCCESS(s2n_stuffer_free(&input));
        };

        /* Read what we write */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, protocol1, sizeof(protocol1)));
            EXPECT_SUCCESS(s2n_client_alpn_extension.send(conn, &conn->handshake.io));

            /* Skip list size */
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&conn->handshake.io, sizeof(uint16_t)));

            struct s2n_blob result = { 0 };
            EXPECT_OK(s2n_protocol_preferences_read(&conn->handshake.io, &result));
            EXPECT_EQUAL(result.size, sizeof(protocol1));
            EXPECT_BYTEARRAY_EQUAL(result.data, protocol1, sizeof(protocol1));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* s2n_protocol_preferences_contain */
    {
        uint8_t protocol3[] = "protocol3";
        struct s2n_blob protocol3_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&protocol3_blob, protocol3, sizeof(protocol3)));

        /* Safety checks */
        {
            struct s2n_blob blob = { 0 };
            bool match = false;
            EXPECT_ERROR_WITH_ERRNO(s2n_protocol_preferences_contain(NULL, &blob, &match), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_protocol_preferences_contain(&blob, NULL, &match), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_protocol_preferences_contain(&blob, &blob, NULL), S2N_ERR_NULL);
        };

        /* No supported protocols */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);

            bool result = true;
            EXPECT_OK(s2n_protocol_preferences_contain(&conn->application_protocols_overridden, &protocol3_blob, &result));
            EXPECT_FALSE(result);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* No match */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);

            EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, protocol1, sizeof(protocol1)));
            EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, protocol2, sizeof(protocol2)));

            bool result = true;
            EXPECT_OK(s2n_protocol_preferences_contain(&conn->application_protocols_overridden, &protocol3_blob, &result));
            EXPECT_FALSE(result);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Match */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);

            EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, protocol1, sizeof(protocol1)));
            EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, protocol2, sizeof(protocol2)));
            EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, protocol3, sizeof(protocol3)));

            bool result = false;
            EXPECT_OK(s2n_protocol_preferences_contain(&conn->application_protocols_overridden, &protocol3_blob, &result));
            EXPECT_TRUE(result);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    END_TEST();
    return 0;
}
