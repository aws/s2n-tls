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

#include "tls/extensions/s2n_server_supported_versions.h"
#include "tls/extensions/s2n_supported_versions.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"

#include "utils/s2n_safety.h"

/**
 * Specified in https://tools.ietf.org/html/rfc8446#section-4.2.1
 *
 * "A server which negotiates TLS 1.3 MUST respond by sending a 
 * "supported_versions" extension containing the selected version value 
 * (0x0304)."
 *
 * Structure:
 * Extension type (2 bytes)
 * Extension size (2 bytes)
 * Selected Version (2 byte)
 **/

int s2n_extensions_server_supported_versions_size()
{
    return 6;
}

int s2n_extensions_server_supported_versions_process(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint8_t highest_supported_version = conn->client_protocol_version;
    uint8_t minimum_supported_version;
    GUARD(s2n_connection_get_minimum_supported_version(conn, &minimum_supported_version));

    uint8_t server_version_parts[S2N_TLS_PROTOCOL_VERSION_LEN];
    GUARD(s2n_stuffer_read_bytes(extension, server_version_parts, S2N_TLS_PROTOCOL_VERSION_LEN));

    uint16_t server_version = (server_version_parts[0] * 10) + server_version_parts[1];

    gte_check(server_version, S2N_TLS13);
    lte_check(server_version, highest_supported_version);
    gte_check(server_version, minimum_supported_version);

    conn->server_protocol_version = server_version;
    
    return 0;
}

int s2n_extensions_server_supported_versions_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    S2N_ERROR_IF(s2n_extensions_server_supported_versions_process(conn, extension) < 0, S2N_ERR_BAD_MESSAGE);

    return 0;
}

int s2n_extensions_server_supported_versions_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    int extension_length = s2n_extensions_server_supported_versions_size();

    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SUPPORTED_VERSIONS));
    GUARD(s2n_stuffer_write_uint16(out, extension_length - 4));

    GUARD(s2n_stuffer_write_uint8(out, conn->server_protocol_version / 10));
    GUARD(s2n_stuffer_write_uint8(out, conn->server_protocol_version % 10));

    return 0;
}
