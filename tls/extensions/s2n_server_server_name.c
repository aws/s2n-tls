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

#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_connection.h"
#include "tls/extensions/s2n_server_server_name.h"

#define s2n_server_can_send_server_name(conn) ((conn)->server_name_used && \
        !s2n_connection_is_session_resumed((conn)))

int s2n_server_extensions_server_name_send_size(struct s2n_connection *conn) {
    if (!s2n_server_can_send_server_name(conn)) {
        return 0;
    }

    return 2 * sizeof(uint16_t);
}

int s2n_server_extensions_server_name_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    if (!s2n_server_can_send_server_name(conn)) {
        return 0;
    }

    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SERVER_NAME));
    GUARD(s2n_stuffer_write_uint16(out, 0));

    return 0;
}

int s2n_recv_server_server_name(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    conn->server_name_used = 1;
    return 0;
}
