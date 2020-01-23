/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <sys/param.h>
#include <stdint.h>

#include "tls/extensions/s2n_client_alpn.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"

#include "utils/s2n_safety.h"

int s2n_extensions_client_alpn_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    struct s2n_blob *client_app_protocols;
    GUARD(s2n_connection_get_protocol_preferences(conn, &client_app_protocols));
    uint16_t application_protocols_len = client_app_protocols->size;

    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_ALPN));
    GUARD(s2n_stuffer_write_uint16(out, application_protocols_len + 2));
    GUARD(s2n_stuffer_write_uint16(out, application_protocols_len));
    GUARD(s2n_stuffer_write(out, client_app_protocols));

    return 0;
}

int s2n_recv_client_alpn(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint16_t size_of_all;
    struct s2n_stuffer client_protos = {0};
    struct s2n_stuffer server_protos = {0};

    struct s2n_blob *server_app_protocols;
    GUARD(s2n_connection_get_protocol_preferences(conn, &server_app_protocols));

    if (!server_app_protocols->size) {
        /* No protocols configured, nothing to do */
        return 0;
    }

    GUARD(s2n_stuffer_read_uint16(extension, &size_of_all));
    if (size_of_all > s2n_stuffer_data_available(extension) || size_of_all < 3) {
        /* Malformed length, ignore the extension */
        return 0;
    }

    struct s2n_blob client_app_protocols = { 0 };
    client_app_protocols.size = size_of_all;
    client_app_protocols.data = s2n_stuffer_raw_read(extension, size_of_all);
    notnull_check(client_app_protocols.data);

    /* Find a matching protocol */
    GUARD(s2n_stuffer_init(&client_protos, &client_app_protocols));
    GUARD(s2n_stuffer_write(&client_protos, &client_app_protocols));
    GUARD(s2n_stuffer_init(&server_protos, server_app_protocols));
    GUARD(s2n_stuffer_write(&server_protos, server_app_protocols));

    while (s2n_stuffer_data_available(&server_protos)) {
        uint8_t length;
        uint8_t server_protocol[255];
        GUARD(s2n_stuffer_read_uint8(&server_protos, &length));
        GUARD(s2n_stuffer_read_bytes(&server_protos, server_protocol, length));

        while (s2n_stuffer_data_available(&client_protos)) {
            uint8_t client_length;
            GUARD(s2n_stuffer_read_uint8(&client_protos, &client_length));
            S2N_ERROR_IF(client_length > s2n_stuffer_data_available(&client_protos), S2N_ERR_BAD_MESSAGE);
            if (client_length != length) {
                GUARD(s2n_stuffer_skip_read(&client_protos, client_length));
            } else {
                uint8_t client_protocol[255];
                GUARD(s2n_stuffer_read_bytes(&client_protos, client_protocol, client_length));
                if (memcmp(client_protocol, server_protocol, client_length) == 0) {
                    memcpy_check(conn->application_protocol, client_protocol, client_length);
                    conn->application_protocol[client_length] = '\0';
                    return 0;
                }
            }
        }

        GUARD(s2n_stuffer_reread(&client_protos));
    }
    return 0;
}
