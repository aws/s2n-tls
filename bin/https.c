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

#include <s2n.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define STRING_LEN 1024
static char str_buffer[STRING_LEN];

#define REPLY(...) sprintf(str_buffer, __VA_ARGS__);\
    s2n_send(conn, str_buffer, strlen(str_buffer), &blocked);

/*
 * simple https handler that allows https clients to connect
 * but currently does not do any user parsing
 */
int https(struct s2n_connection *conn, uint32_t bench)
{
    const char header[] = "HTTP/1.0 200 OK\r\n\r\n";
    const char response[] = "<html><body><h1>Hello from s2n server</h1><pre>";

    s2n_blocked_status blocked;

    REPLY(header);
    REPLY(response);

    REPLY("Client hello version: %d\n", s2n_connection_get_client_hello_version(conn));
    REPLY("Client protocol version: %d\n", s2n_connection_get_client_protocol_version(conn));
    REPLY("Server protocol version: %d\n", s2n_connection_get_server_protocol_version(conn));
    REPLY("Actual protocol version: %d\n", s2n_connection_get_actual_protocol_version(conn));

    if (s2n_get_server_name(conn)) {
        REPLY("Server name: %s\n", s2n_get_server_name(conn));
    }

    if (s2n_get_application_protocol(conn)) {
        REPLY("Application protocol: %s\n", s2n_get_application_protocol(conn));
    }

    REPLY("Curve: %s\n", s2n_connection_get_curve(conn));
    REPLY("KEM:%s\n ", s2n_connection_get_kem_name(conn));
    REPLY("Cipher negotiated: %s\n", s2n_connection_get_cipher(conn));

    /* In bench mode, we send some binary output */
    if (bench == 0) return 0;

    fprintf(stdout, "Sending %u bytes...\n", bench);

    uint8_t big_buff[65536] = { 0 };
    uint32_t len = sizeof(big_buff);
    uint32_t bytes_sent = 0;

    while (bytes_sent < bench) {
        uint32_t i = 0;

        while (i < len) {
            int out = s2n_send(conn, &big_buff[i], len - i, &blocked);
            if (out < 0) {
                fprintf(stderr, "Error writing to connection: '%s'\n", s2n_strerror(s2n_errno, "EN"));
                s2n_print_stacktrace(stdout);
                return 1;
            }
            i += out;
        }

        bytes_sent += i;
    }

    fprintf(stdout, "Done. Closing connection.\n\n");

    return 0;
}
