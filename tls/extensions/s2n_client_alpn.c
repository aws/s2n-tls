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

#include <sys/param.h>
#include <stdint.h>

#include "tls/extensions/s2n_client_alpn.h"

#include "tls/extensions/s2n_extension_type.h"
#include "tls/s2n_protocol_preferences.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"

#include "utils/s2n_safety.h"

static bool s2n_client_alpn_should_send(struct s2n_connection *conn);
static int s2n_client_alpn_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static int s2n_client_alpn_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

const s2n_extension_type s2n_client_alpn_extension = {
    .iana_value = TLS_EXTENSION_ALPN,
    .is_response = false,
    .send = s2n_client_alpn_send,
    .recv = s2n_client_alpn_recv,
    .should_send = s2n_client_alpn_should_send,
    .if_missing = s2n_extension_noop_if_missing,
};

static bool s2n_client_alpn_should_send(struct s2n_connection *conn)
{
    struct s2n_blob *client_app_protocols;

    return s2n_connection_get_protocol_preferences(conn, &client_app_protocols) == S2N_SUCCESS
            && client_app_protocols->size != 0 && client_app_protocols->data != NULL;
}

static int s2n_client_alpn_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    struct s2n_blob *client_app_protocols;
    POSIX_GUARD(s2n_connection_get_protocol_preferences(conn, &client_app_protocols));
    POSIX_ENSURE_REF(client_app_protocols);

    POSIX_GUARD(s2n_stuffer_write_uint16(out, client_app_protocols->size));
    POSIX_GUARD(s2n_stuffer_write(out, client_app_protocols));

    return S2N_SUCCESS;
}

static int s2n_client_alpn_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint16_t size_of_all;
    struct s2n_stuffer server_protos = {0};

    struct s2n_blob *server_app_protocols;
    POSIX_GUARD(s2n_connection_get_protocol_preferences(conn, &server_app_protocols));

    if (!server_app_protocols->size) {
        /* No protocols configured, nothing to do */
        return S2N_SUCCESS;
    }

    POSIX_GUARD(s2n_stuffer_read_uint16(extension, &size_of_all));
    if (size_of_all > s2n_stuffer_data_available(extension) || size_of_all < 3) {
        /* Malformed length, ignore the extension */
        return S2N_SUCCESS;
    }

    struct s2n_blob client_app_protocols = { 0 };
    client_app_protocols.size = size_of_all;
    client_app_protocols.data = s2n_stuffer_raw_read(extension, size_of_all);
    POSIX_ENSURE_REF(client_app_protocols.data);

    /* Find a matching protocol */
    POSIX_GUARD(s2n_stuffer_init(&server_protos, server_app_protocols));
    POSIX_GUARD(s2n_stuffer_skip_write(&server_protos, server_app_protocols->size));

    while (s2n_stuffer_data_available(&server_protos) > 0) {
        struct s2n_blob server_protocol = { 0 };
        POSIX_ENSURE(s2n_result_is_ok(s2n_protocol_preferences_read(&server_protos, &server_protocol)),
                S2N_ERR_BAD_MESSAGE);

        bool is_match = false;
        POSIX_ENSURE(s2n_result_is_ok(s2n_protocol_preferences_contain(&client_app_protocols, &server_protocol, &is_match)),
                S2N_ERR_BAD_MESSAGE);

        if (is_match) {
            POSIX_CHECKED_MEMCPY(conn->application_protocol, server_protocol.data, server_protocol.size);
            conn->application_protocol[server_protocol.size] = '\0';
            return S2N_SUCCESS;
        }
    }
    return S2N_SUCCESS;
}

/* Old-style extension functions -- remove after extensions refactor is complete */

int s2n_extensions_client_alpn_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    return s2n_extension_send(&s2n_client_alpn_extension, conn, out);
}

int s2n_recv_client_alpn(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    return s2n_extension_recv(&s2n_client_alpn_extension, conn, extension);
}
