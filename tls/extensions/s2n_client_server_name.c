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

#include "tls/extensions/s2n_client_server_name.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"

#include "utils/s2n_safety.h"

int s2n_extensions_client_server_name_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    uint16_t server_name_len = strlen(conn->server_name);

    /* Write the server name */
    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SERVER_NAME));
    GUARD(s2n_stuffer_write_uint16(out, server_name_len + 5));

    /* Size of all of the server names */
    GUARD(s2n_stuffer_write_uint16(out, server_name_len + 3));

    /* Name type - host name, RFC3546 */
    GUARD(s2n_stuffer_write_uint8(out, 0));

    struct s2n_blob server_name = {0};
    server_name.data = (uint8_t *) conn->server_name;
    server_name.size = server_name_len;
    GUARD(s2n_stuffer_write_uint16(out, server_name_len));
    GUARD(s2n_stuffer_write(out, &server_name));

    return 0;
}

int s2n_parse_client_hello_server_name(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    if (conn->server_name[0]) {
        /* already parsed server name extension, exit early */
        return 0;
    }

    uint16_t size_of_all;
    uint8_t server_name_type;
    uint16_t server_name_len;
    uint8_t *server_name;

    GUARD(s2n_stuffer_read_uint16(extension, &size_of_all));
    if (size_of_all > s2n_stuffer_data_available(extension) || size_of_all < 3) {
        /* the size of all server names is incorrect, ignore the extension */
        return 0;
    }

    GUARD(s2n_stuffer_read_uint8(extension, &server_name_type));
    if (server_name_type != 0) {
        /* unknown server name type, ignore the extension */
        return 0;
    }

    GUARD(s2n_stuffer_read_uint16(extension, &server_name_len));
    if (server_name_len + 3 > size_of_all) {
        /* the server name length is incorrect, ignore the extension */
        return 0;
    }

    if (server_name_len > sizeof(conn->server_name) - 1) {
        /* the server name is too long, ignore the extension */
        return 0;
    }

    notnull_check(server_name = s2n_stuffer_raw_read(extension, server_name_len));

    /* copy the first server name */
    memcpy_check(conn->server_name, server_name, server_name_len);
    return 0;
}
