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
char str[STRING_LEN];

#define REPLY(format, var) sprintf(str, "%s %d\n", format, var);\
    s2n_send(conn, str, strlen(str), &blocked);

#define REPLY_STR(format, var) sprintf(str, "%s %s\n", format, var);\
    s2n_send(conn, str, strlen(str), &blocked);

int https(struct s2n_connection *conn, bool bench)
{
    printf("https\n");
    const char header[] = "HTTP/1.1 200 OK\r\n\r\n";
    const char response[] = "<html><body><h1>Hello from s2n server</h1><pre>";

    s2n_blocked_status blocked;

    s2n_send(conn, header, strlen(header), &blocked);
    s2n_send(conn, response, strlen(response), &blocked);

    REPLY("Client hello version: ", s2n_connection_get_client_hello_version(conn));
    REPLY("Client protocol version: ", s2n_connection_get_client_protocol_version(conn));
    REPLY("Server protocol version: ", s2n_connection_get_server_protocol_version(conn));
    REPLY("Actual protocol version: ", s2n_connection_get_actual_protocol_version(conn));

    if (s2n_get_server_name(conn)) {
        REPLY_STR("Server name: ", s2n_get_server_name(conn));
    }

    if (s2n_get_application_protocol(conn)) {
        REPLY_STR("Application protocol: ", s2n_get_application_protocol(conn));
    }

    REPLY_STR("Curve: ", s2n_connection_get_curve(conn));
    REPLY_STR("KEM: ", s2n_connection_get_kem_name(conn));
    REPLY_STR("Cipher negotiated: ", s2n_connection_get_cipher(conn));

    return 0;
}
