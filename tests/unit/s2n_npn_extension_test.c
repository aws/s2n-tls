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

#include <stdint.h>
#include <string.h>

#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tests/s2n_test.h"
#include "tls/extensions/s2n_client_alpn.h"
#include "tls/extensions/s2n_npn.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

#define HTTP11 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31
#define SPDY1  0x73, 0x70, 0x64, 0x79, 0x2f, 0x31
#define SPDY2  0x73, 0x70, 0x64, 0x79, 0x2f, 0x32
#define SPDY3  0x73, 0x70, 0x64, 0x79, 0x2f, 0x33

S2N_RESULT s2n_calculate_padding(uint8_t protocol_len, uint8_t *padding_len);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const char *protocols[] = { "http/1.1", "spdy/1", "spdy/2" };
    const uint8_t protocols_count = s2n_array_len(protocols);

    /* Should-send tests on the client side */
    {
        /* No connection */
        EXPECT_FALSE(s2n_client_npn_extension.should_send(NULL));

        /* No config */
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_FALSE(s2n_client_npn_extension.should_send(client_conn));

        /* No application protocols set */
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_FALSE(s2n_client_npn_extension.should_send(client_conn));

        /* Application protocols set but NPN not supported. In this case the ALPN extension will be sent. */
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
        EXPECT_FALSE(s2n_client_npn_extension.should_send(client_conn));
        EXPECT_TRUE(s2n_client_alpn_extension.should_send(client_conn));

        /* Both ALPN and NPN extensions will be sent */
        client_conn->config->npn_supported = true;
        EXPECT_TRUE(s2n_client_npn_extension.should_send(client_conn));
        EXPECT_TRUE(s2n_client_alpn_extension.should_send(client_conn));

        /*
         *= https://datatracker.ietf.org/doc/id/draft-agl-tls-nextprotoneg-03#section-3
         *= type=test
         *# For the same reasons, after a handshake has been performed for a
         *# given connection, renegotiations on the same connection MUST NOT
         *# include the "next_protocol_negotiation" extension.
         */
        client_conn->handshake.renegotiation = true;
        EXPECT_FALSE(s2n_client_npn_extension.should_send(client_conn));
        EXPECT_TRUE(s2n_client_alpn_extension.should_send(client_conn));
    };

    /* s2n_client_npn_recv */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

        /* NPN not supported */
        EXPECT_SUCCESS(s2n_client_npn_extension.recv(server_conn, &extension));
        EXPECT_FALSE(server_conn->npn_negotiated);

        /* NPN supported */
        server_conn->config->npn_supported = true;
        EXPECT_SUCCESS(s2n_client_npn_extension.recv(server_conn, &extension));
        EXPECT_TRUE(server_conn->npn_negotiated);

        /* Server has already negotiated a protocol with the ALPN extension */
        uint8_t first_protocol_len = strlen(protocols[0]);
        EXPECT_MEMCPY_SUCCESS(server_conn->application_protocol, protocols[0], first_protocol_len + 1);
        server_conn->npn_negotiated = false;
        EXPECT_SUCCESS(s2n_client_npn_extension.recv(server_conn, &extension));
        EXPECT_FALSE(server_conn->npn_negotiated);
    };

    /* Should-send tests on the server side */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* NPN not negotiated */
        EXPECT_FALSE(s2n_server_npn_extension.should_send(server_conn));

        /* NPN negotiated */
        server_conn->npn_negotiated = true;
        EXPECT_TRUE(s2n_server_npn_extension.should_send(server_conn));
    };

    /* s2n_server_npn_send */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

        EXPECT_SUCCESS(s2n_server_npn_extension.send(server_conn, &out));

        uint8_t protocol_len = 0;
        uint8_t protocol[UINT8_MAX] = { 0 };
        for (size_t i = 0; i < protocols_count; i++) {
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &protocol_len));
            EXPECT_EQUAL(protocol_len, strlen(protocols[i]));

            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&out, protocol, protocol_len));
            EXPECT_BYTEARRAY_EQUAL(protocol, protocols[i], protocol_len);
        }

        EXPECT_EQUAL(s2n_stuffer_data_available(&out), 0);
    };

    /* s2n_server_npn_recv */
    {
        /* Client has no application protocols configured. Not sure how this
         * could happen, but added to be thorough. */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

            EXPECT_SUCCESS(s2n_server_npn_extension.recv(client_conn, &extension));
            EXPECT_NULL(s2n_get_application_protocol(client_conn));
        };

        /* NPN recv extension can read NPN send extension */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

            EXPECT_SUCCESS(s2n_server_npn_extension.send(client_conn, &extension));
            EXPECT_SUCCESS(s2n_server_npn_extension.recv(client_conn, &extension));

            /* Server sent the same list that the client configured so the first protocol in the list is chosen */
            EXPECT_NOT_NULL(s2n_get_application_protocol(client_conn));
            EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(client_conn), protocols[0], strlen(protocols[0]));
        };

        /* No match exists */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

            uint8_t protocol[] = { SPDY3 };
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, sizeof(protocol)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&extension, protocol, sizeof(protocol)));

            /*
             *= https://datatracker.ietf.org/doc/id/draft-agl-tls-nextprotoneg-03#section-4
             *= type=test
             *# In the event that the client doesn't support any of server's protocols, or
             *# the server doesn't advertise any, it SHOULD select the first protocol
             *# that it supports.
             */
            EXPECT_SUCCESS(s2n_server_npn_extension.recv(client_conn, &extension));
            EXPECT_NOT_NULL(s2n_get_application_protocol(client_conn));
            EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(client_conn), protocols[0], strlen(protocols[0]));
        };

        /* Server sends empty list */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

            /*
             *= https://datatracker.ietf.org/doc/id/draft-agl-tls-nextprotoneg-03#section-4
             *= type=test
             *# In the event that the client doesn't support any of server's protocols, or
             *# the server doesn't advertise any, it SHOULD select the first protocol
             *# that it supports.
             */
            EXPECT_SUCCESS(s2n_server_npn_extension.recv(client_conn, &extension));
            EXPECT_NOT_NULL(s2n_get_application_protocol(client_conn));
            EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(client_conn), protocols[0], strlen(protocols[0]));
        };

        /* Multiple matches exist and server's preferred choice is selected */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

            uint8_t wire_bytes[] = {
                /* Size and bytes of first protocol */
                0x06,
                SPDY1,
                /* Size and bytes of second protocol */
                0x08,
                HTTP11,
                /* Size and bytes of second protocol */
                0x06,
                SPDY2,
            };

            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&extension, wire_bytes, sizeof(wire_bytes)));
            EXPECT_SUCCESS(s2n_server_npn_extension.recv(client_conn, &extension));

            EXPECT_NOT_NULL(s2n_get_application_protocol(client_conn));

            /* Client's second protocol is selected because the server prefers it over client's first protocol */
            EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(client_conn), protocols[1], strlen(protocols[1]));
        };
    };

    /* Check application protocol array can hold the largest uint8_t value.
     *
     * We frequently copy a uint8_t's worth of data into this array. Adding
     * checks to ensure that the array will be large enough causes compilers
     * to give warnings that the check will always be true.
     * This test will fail if we ever make that array smaller, so we remember
     * to go back and add those checks.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        /* Not <= because the application protocol is a string, which needs to
         * be terminated by a null character */
        EXPECT_TRUE(UINT8_MAX < sizeof(server_conn->application_protocol));
    };

    END_TEST();
}
