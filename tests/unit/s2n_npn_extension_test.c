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
#include <string.h>

#include "tls/s2n_tls.h"
#include "tls/extensions/s2n_npn.h"
#include "tls/extensions/s2n_client_alpn.h"
#include "testlib/s2n_testlib.h"
#include "tests/s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

#define HTTP11 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31
#define SPDY1 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31
#define SPDY2 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32
#define SPDY3 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33

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
    }

    /* Should-send tests on the server side */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(config, protocols, protocols_count));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        
        /* NPN not supported */
        EXPECT_FALSE(s2n_server_npn_extension.should_send(server_conn));

        /* NPN supported */
        server_conn->config->npn_supported = true;
        EXPECT_TRUE(s2n_server_npn_extension.should_send(server_conn));

        /* Server has already negotiated a protocol with the ALPN extension */
        uint8_t first_protocol_len = strlen(protocols[0]);
        EXPECT_MEMCPY_SUCCESS(server_conn->application_protocol, protocols[0], first_protocol_len + 1);
        EXPECT_FALSE(s2n_server_npn_extension.should_send(server_conn));
    }

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
    }

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
        }

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
        }

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

            EXPECT_SUCCESS(s2n_server_npn_extension.recv(client_conn, &extension));

            /*
             *= https://datatracker.ietf.org/doc/id/draft-agl-tls-nextprotoneg-04#section-4
             *= type=test
             *# In the event that the client doesn't support any of server's protocols, or
             *# the server doesn't advertise any, it SHOULD select the first protocol
             *# that it supports.
             */
            EXPECT_NOT_NULL(s2n_get_application_protocol(client_conn));
            EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(client_conn), protocols[0], strlen(protocols[0]));
        }

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
                0x06, SPDY1,
                /* Size and bytes of second protocol */
                0x08,  HTTP11,
                /* Size and bytes of second protocol */
                0x06, SPDY2,
                };

            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&extension, wire_bytes, sizeof(wire_bytes)));
            EXPECT_SUCCESS(s2n_server_npn_extension.recv(client_conn, &extension));

            EXPECT_NOT_NULL(s2n_get_application_protocol(client_conn));

            /* Client's second protocol is selected because the server prefers it over client's first protocol */
            EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(client_conn), protocols[1], strlen(protocols[1]));
        }
    }

    /* Tests for the NPN extension on the Encrypted Extensions handshake message */
    {
        /* s2n_npn_encrypted_should_send */
        {
            /* No connection */
            EXPECT_FALSE(s2n_npn_encrypted_extension.should_send(NULL));

            /* No chosen application protocol */
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_FALSE(s2n_npn_encrypted_extension.should_send(client_conn));

            /* Should send if protocol has been negotiated */
            uint8_t first_protocol_len = strlen(protocols[0]);
            EXPECT_MEMCPY_SUCCESS(client_conn->application_protocol, protocols[0], first_protocol_len + 1);
            EXPECT_TRUE(s2n_npn_encrypted_extension.should_send(client_conn));
        }

        /* s2n_npn_encrypted_extension_send */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);

            uint8_t first_protocol_len = strlen(protocols[0]);
            EXPECT_MEMCPY_SUCCESS(client_conn->application_protocol, protocols[0], first_protocol_len + 1);

            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_npn_encrypted_extension.send(client_conn, &out));

            uint8_t protocol_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &protocol_len));

            uint8_t protocol[UINT8_MAX] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&out, protocol, protocol_len));
            EXPECT_BYTEARRAY_EQUAL(protocol, protocols[0], protocol_len);

            uint8_t padding_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &padding_len));
            EXPECT_TRUE(padding_len > 0);
            
            for(size_t i = 0; i < padding_len; i++) {
                uint8_t byte = UINT8_MAX;
                EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &byte));
                EXPECT_EQUAL(byte, 0);
            }
            EXPECT_EQUAL(s2n_stuffer_data_available(&out), 0);
        }

        /* NPN Encrypted Extension recv can read NPN Encrypted Extension send */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            uint8_t first_protocol_len = strlen(protocols[0]);
            EXPECT_MEMCPY_SUCCESS(client_conn->application_protocol, protocols[0], first_protocol_len + 1);

            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_npn_encrypted_extension.send(client_conn, &out));
            EXPECT_SUCCESS(s2n_npn_encrypted_extension.recv(server_conn, &out));

            EXPECT_NOT_NULL(s2n_get_application_protocol(server_conn));
            EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(server_conn), protocols[0], strlen(protocols[0]));
        }

        /* NPN Encrypted Extension recv can read empty extension */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            /* Zero-length protocol */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, 0));
            uint8_t padding_len = 0;
            EXPECT_OK(s2n_calculate_padding(0, &padding_len));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, padding_len));
            for(size_t i = 0; i < padding_len; i++) {
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, 0));
            }

            EXPECT_SUCCESS(s2n_npn_encrypted_extension.recv(server_conn, &out));
            EXPECT_NULL(s2n_get_application_protocol(server_conn));
        }

        /* NPN Encrypted Extension recv errors on malformed extension */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            uint8_t wire_bytes[] = {
                /* Incorrect length of extension */
                0x10,
            };

            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&out, wire_bytes, sizeof(wire_bytes)));
            EXPECT_FAILURE_WITH_ERRNO(s2n_npn_encrypted_extension.recv(server_conn, &out), S2N_ERR_NULL);
        }

        /* NPN Encrypted Extension recv errors on malformed padding */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            uint8_t wire_bytes[] = {
                /* Zero-length protocol */
                0x00, 0x00,
                /* Padding character is not zero */
                0x01, 0xFF,
            };

            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&out, wire_bytes, sizeof(wire_bytes)));
            EXPECT_FAILURE_WITH_ERRNO(s2n_npn_encrypted_extension.recv(server_conn, &out), S2N_ERR_SAFETY);
        }

        /*
         *= https://datatracker.ietf.org/doc/id/draft-agl-tls-nextprotoneg-04#section-3
         *= type=test
         *# The length of "padding" SHOULD be 32 - ((len(selected_protocol) + 2) % 32).
         */
        {
            struct {
                uint8_t protocol_len;
                uint8_t expected_padding;
            } test_cases[] = {
                { .protocol_len = 0, .expected_padding = 30 },
                { .protocol_len = 32, .expected_padding = 30 },
                { .protocol_len = 17, .expected_padding = 13 },
                { .protocol_len = 2, .expected_padding = 28 },
                { .protocol_len = UINT8_MAX, .expected_padding = 31 },
                { .protocol_len = 30, .expected_padding = 32 },
            };

            for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
                uint8_t output = 0;
                EXPECT_OK(s2n_calculate_padding(test_cases[i].protocol_len, &output));
                EXPECT_EQUAL(output, test_cases[i].expected_padding);
            }
        }
    }

    END_TEST();
}
