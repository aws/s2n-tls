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

#include "tls/s2n_alerts.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_tls.h"
#include "tls/extensions/s2n_client_supported_versions.h"

#include "utils/s2n_safety.h"

/**
 * Specified in https://tools.ietf.org/html/rfc8446#section-4.2.1
 *
 * "The "supported_versions" extension is used by the client to indicate
 * which versions of TLS it supports and by the server to indicate which
 * version it is using. The extension contains a list of supported
 * versions in preference order, with the most preferred version first."
 **/

uint8_t s2n_supported_protocol_versions[] = { S2N_TLS13, S2N_TLS12, S2N_TLS11, S2N_TLS10, S2N_SSLv3, S2N_SSLv2 };

int s2n_extensions_client_supported_versions_process(struct s2n_connection *conn, struct s2n_stuffer *extension) {
    uint8_t size_of_version_list = 0;
    GUARD(s2n_stuffer_read_uint8(extension, &size_of_version_list));

    conn->client_protocol_version = s2n_unknown_protocol_version;
    conn->actual_protocol_version = s2n_unknown_protocol_version;

    for (int i = 0; i < size_of_version_list; i += S2N_TLS_PROTOCOL_VERSION_LEN) {
        uint8_t client_version_parts[S2N_TLS_PROTOCOL_VERSION_LEN];
        GUARD(s2n_stuffer_read_bytes(extension, client_version_parts, S2N_TLS_PROTOCOL_VERSION_LEN));

        uint16_t client_version = (client_version_parts[0] * 10) + client_version_parts[1];

        conn->client_protocol_version = MAX(client_version, conn->client_protocol_version);

        if (client_version > s2n_supported_protocol_versions[0]) {
            continue;
        }

        /* We ignore the client's preferred order and instead choose
         * the highest version that both client and server support. */
        conn->actual_protocol_version = MAX(client_version, conn->actual_protocol_version);
    }

    if (conn->actual_protocol_version == s2n_unknown_protocol_version) {
        return -1;
    }

    return 0;
}

int get_supported_version_list_length() {
    return sizeof(s2n_supported_protocol_versions);
}

int get_supported_version_list_size() {
    return get_supported_version_list_length() * S2N_TLS_PROTOCOL_VERSION_LEN;
}

int get_extension_data_size() {
    /*
     * Full size:
     * Version list size (1 byte)
     * Version list (variable)
     */
    return get_supported_version_list_size() + 1;
}

int s2n_extensions_client_supported_versions_size(struct s2n_connection *conn) {
    /*
     * Full size:
     * Extension type (2 bytes) +
     * Extension data size (2 bytes) +
     * Extension data (variable)
     */
    return get_extension_data_size() + 4;
}

int s2n_extensions_client_supported_versions_recv(struct s2n_connection *conn, struct s2n_stuffer *extension) {
    if (s2n_extensions_client_supported_versions_process(conn, extension) < 0) {
        s2n_queue_reader_unsupported_protocol_version_alert(conn);
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }
    return 0;
}

int s2n_extensions_client_supported_versions_send(struct s2n_connection *conn, struct s2n_stuffer *out) {
    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SUPPORTED_VERSIONS));

    GUARD(s2n_stuffer_write_uint16(out, get_extension_data_size()));
    GUARD(s2n_stuffer_write_uint8(out, get_supported_version_list_size()));

    for (int i = 0; i < get_supported_version_list_length(); i++) {
        GUARD(s2n_stuffer_write_uint8(out, s2n_supported_protocol_versions[i] / 10));
        GUARD(s2n_stuffer_write_uint8(out, s2n_supported_protocol_versions[i] % 10));
    }

    return 0;
}
