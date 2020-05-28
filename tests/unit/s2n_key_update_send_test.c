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

#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>

#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13());
    
    struct s2n_connection *server_conn;
    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

    struct s2n_stuffer client_to_server;
    struct s2n_stuffer server_to_client;

    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_to_server, 0));
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_to_client, 0));
    server_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
    server_conn->actual_protocol_version = S2N_TLS13;
                                       
    EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));

    /* Mimic key update send conditions */
    server_conn->encrypted_bytes_out = S2N_TLS13_AES_GCM_MAXIMUM_BYTES_TO_ENCRYPT;

    /* Next message to send will trigger key update message*/
    s2n_blocked_status blocked;
    char message[] = "sent message";
    EXPECT_SUCCESS(s2n_send(server_conn, message, sizeof(message), &blocked));
    EXPECT_NOT_EQUAL(server_conn->encrypted_bytes_out, S2N_TLS13_AES_GCM_MAXIMUM_BYTES_TO_ENCRYPT);
    
    /* Parse key update message */
    uint8_t handshake_id;
    EXPECT_SUCCESS(s2n_stuffer_read_uint8(&server_to_client, &handshake_id));
    EXPECT_EQUAL(handshake_id, TLS_HANDSHAKE);

    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    EXPECT_SUCCESS(s2n_stuffer_read_bytes(&server_to_client, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));
    EXPECT_EQUAL(protocol_version[0] * 10 + protocol_version[1], S2N_TLS12);
    
    uint16_t message_length;
    EXPECT_SUCCESS(s2n_stuffer_read_uint16(&server_to_client, &message_length));
    EXPECT_EQUAL(message_length, S2N_KEY_UPDATE_MESSAGE_SIZE);

    uint8_t post_handshake_id;
    EXPECT_SUCCESS(s2n_stuffer_read_uint8(&server_to_client, &post_handshake_id));
    EXPECT_EQUAL(post_handshake_id, TLS_KEY_UPDATE);

    uint32_t request_length;
    EXPECT_SUCCESS(s2n_stuffer_read_uint24(&server_to_client, &request_length));
    EXPECT_EQUAL(request_length, S2N_KEY_UPDATE_LENGTH);

    uint8_t key_update_request;
    EXPECT_SUCCESS(s2n_stuffer_read_uint8(&server_to_client, &key_update_request));
    EXPECT_EQUAL(key_update_request, S2N_KEY_UPDATE_NOT_REQUESTED);

    /* Parse the sent message that triggered the keyupdate message*/
    uint8_t message_id;
    EXPECT_SUCCESS(s2n_stuffer_read_uint8(&server_to_client, &message_id));
    EXPECT_EQUAL(message_id, TLS_APPLICATION_DATA);

    EXPECT_SUCCESS(s2n_stuffer_read_bytes(&server_to_client, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));
    EXPECT_EQUAL(protocol_version[0] * 10 + protocol_version[1], S2N_TLS12);

    EXPECT_SUCCESS(s2n_stuffer_read_uint16(&server_to_client, &message_length));
    EXPECT_EQUAL((int)message_length, sizeof(message));

    uint8_t message_bytes;
    for (int i = 0; i < sizeof(message); i++) {
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&server_to_client, &message_bytes));
        EXPECT_EQUAL(message_bytes, message[i]);
    }

    /* Clean up */
    EXPECT_SUCCESS(s2n_connection_free(server_conn));

    END_TEST();
}


