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

#include "tls/extensions/s2n_npn.h"
#include "tls/extensions/s2n_client_alpn.h"
#include "tls/extensions/s2n_server_alpn.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_protocol_preferences.h"

#include "utils/s2n_safety.h"

bool s2n_server_npn_should_send(struct s2n_connection *conn)
{
    /* Only use the NPN extension to negotiate a protocol if the client didn't
     * send the ALPN extension.
     */
    return s2n_npn_should_send(conn) && !s2n_alpn_should_send(conn);
}

int s2n_server_npn_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    struct s2n_blob *app_protocols;
    POSIX_GUARD(s2n_connection_get_protocol_preferences(conn, &app_protocols));
    POSIX_ENSURE_REF(app_protocols);

    POSIX_GUARD(s2n_stuffer_write(out, app_protocols));

    return S2N_SUCCESS;
}

int s2n_server_npn_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    struct s2n_blob *app_protocols;
    POSIX_GUARD(s2n_connection_get_protocol_preferences(conn, &app_protocols));

    if (app_protocols->size == 0) {
        /* No protocols configured */
        return S2N_SUCCESS;
    }

    struct s2n_blob server_protocols = { 0 };
    uint16_t wire_size = s2n_stuffer_data_available(extension);
    server_protocols.size = wire_size;
    server_protocols.data = s2n_stuffer_raw_read(extension, wire_size);
    POSIX_ENSURE_REF(server_protocols.data);

    struct s2n_stuffer client_protocols = { 0 };
    POSIX_GUARD(s2n_stuffer_init(&client_protocols, app_protocols));
    POSIX_GUARD(s2n_stuffer_skip_write(&client_protocols, app_protocols->size));

    while(s2n_stuffer_data_available(&client_protocols) > 0) {
        struct s2n_blob protocol = { 0 };
        POSIX_ENSURE(s2n_result_is_ok(s2n_protocol_preferences_read(&client_protocols, &protocol)), S2N_ERR_BAD_MESSAGE);
        
        bool match_found = false;
        POSIX_ENSURE(s2n_result_is_ok(s2n_protocol_preferences_contain(&server_protocols, &protocol, &match_found)), S2N_ERR_BAD_MESSAGE);
        
        if (match_found) {
            POSIX_CHECKED_MEMCPY(conn->application_protocol, protocol.data, protocol.size);
            conn->application_protocol[protocol.size] = '\0';
            return S2N_SUCCESS;
        }    
    }
    return S2N_SUCCESS;
}

const s2n_extension_type s2n_server_npn_extension = {
    .iana_value = TLS_EXTENSION_NPN,
    .is_response = true,
    .send = s2n_server_npn_send,
    .recv = s2n_server_npn_recv,
    .should_send = s2n_server_npn_should_send,
    .if_missing = s2n_extension_noop_if_missing,
};
