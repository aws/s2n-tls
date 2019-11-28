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

#include "tls/extensions/s2n_client_supported_versions.h"
#include "tls/extensions/s2n_supported_versions.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"

#include "utils/s2n_safety.h"

/**
 * Specified in https://tools.ietf.org/html/rfc8446#section-4.2.1
 *
 * "The "supported_versions" extension is used by the client to indicate
 * which versions of TLS it supports and by the server to indicate which
 * version it is using. The extension contains a list of supported
 * versions in preference order, with the most preferred version first."
 *
 * Structure:
 * Extension type (2 bytes)
 * Extension size (2 bytes)
 * Version list length (1 byte)
 * Version list (number of versions * 2 bytes)
 *
 * Note: We assume in these functions that the supported version numbers
 * are consecutive. This is true because S2N does not support SSLv2, and
 * is already an assumption made in the old client hello version handling.
 **/

int s2n_extensions_client_supported_versions_size(struct s2n_connection *conn) {
    uint8_t minimum_supported_version;
    GUARD(s2n_connection_get_minimum_supported_version(conn, &minimum_supported_version));
    uint8_t highest_supported_version = conn->client_protocol_version;

    uint8_t version_list_length = highest_supported_version - minimum_supported_version + 1;

    return version_list_length * S2N_TLS_PROTOCOL_VERSION_LEN + 5;
}

int s2n_extensions_client_supported_versions_process(struct s2n_connection *conn, struct s2n_stuffer *extension) {
    uint8_t highest_supported_version = conn->server_protocol_version;
    uint8_t minimum_supported_version;
    GUARD(s2n_connection_get_minimum_supported_version(conn, &minimum_supported_version));

    uint8_t size_of_version_list;
    GUARD(s2n_stuffer_read_uint8(extension, &size_of_version_list));
    S2N_ERROR_IF(size_of_version_list != s2n_stuffer_data_available(extension), S2N_ERR_BAD_MESSAGE);
    S2N_ERROR_IF(size_of_version_list % S2N_TLS_PROTOCOL_VERSION_LEN != 0, S2N_ERR_BAD_MESSAGE);

    conn->client_protocol_version = s2n_unknown_protocol_version;
    conn->actual_protocol_version = s2n_unknown_protocol_version;

    for (int i = 0; i < size_of_version_list; i += S2N_TLS_PROTOCOL_VERSION_LEN) {
        uint8_t client_version_parts[S2N_TLS_PROTOCOL_VERSION_LEN];
        GUARD(s2n_stuffer_read_bytes(extension, client_version_parts, S2N_TLS_PROTOCOL_VERSION_LEN));

        uint16_t client_version = (client_version_parts[0] * 10) + client_version_parts[1];

        conn->client_protocol_version = MAX(client_version, conn->client_protocol_version);

        if (client_version > highest_supported_version) {
            continue;
        }

        if (client_version < minimum_supported_version) {
            continue;
        }

        /* We ignore the client's preferred order and instead choose
         * the highest version that both client and server support. */
        conn->actual_protocol_version = MAX(client_version, conn->actual_protocol_version);
    }

    S2N_ERROR_IF(conn->actual_protocol_version == s2n_unknown_protocol_version, S2N_ERR_UNKNOWN_PROTOCOL_VERSION);

    return 0;
}

int s2n_extensions_client_supported_versions_recv(struct s2n_connection *conn, struct s2n_stuffer *extension) {
    if (s2n_extensions_client_supported_versions_process(conn, extension) < 0) {
        s2n_queue_reader_unsupported_protocol_version_alert(conn);
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }
    return 0;
}

int s2n_extensions_client_supported_versions_send(struct s2n_connection *conn, struct s2n_stuffer *out) {
    uint8_t highest_supported_version = conn->client_protocol_version;
    uint8_t minimum_supported_version;
    GUARD(s2n_connection_get_minimum_supported_version(conn, &minimum_supported_version));

    int extension_length = s2n_extensions_client_supported_versions_size(conn);

    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SUPPORTED_VERSIONS));
    GUARD(s2n_stuffer_write_uint16(out, extension_length - 4));

    GUARD(s2n_stuffer_write_uint8(out, extension_length - 5));
    for (uint8_t i = highest_supported_version; i >= minimum_supported_version; i--) {
        GUARD(s2n_stuffer_write_uint8(out, i / 10));
        GUARD(s2n_stuffer_write_uint8(out, i % 10));
    }

    return 0;
}
