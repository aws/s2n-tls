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

#include "tls/extensions/s2n_npn.h"
#include "tls/extensions/s2n_client_alpn.h"
#include "tls/extensions/s2n_server_alpn.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_protocol_preferences.h"

#include "utils/s2n_safety.h"

bool s2n_npn_should_send(struct s2n_connection *conn)
{
    return s2n_client_alpn_should_send(conn) && conn->config->npn_supported;
}

const s2n_extension_type s2n_client_npn_extension = {
    .iana_value = TLS_EXTENSION_NPN,
    .is_response = false,
    .send = s2n_extension_send_noop,
    .recv = s2n_extension_recv_noop,
    .should_send = s2n_npn_should_send,
    .if_missing = s2n_extension_noop_if_missing,
};

bool s2n_server_npn_should_send(struct s2n_connection *conn)
{
    /* Only use the NPN extension to negotiate a protocol if we don't have
     * an option to use the ALPN extension.
     */
    return s2n_npn_should_send(conn) && !s2n_server_alpn_should_send(conn);
}

int s2n_server_npn_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    struct s2n_blob *app_protocols = NULL;
    POSIX_GUARD(s2n_connection_get_protocol_preferences(conn, &app_protocols));
    POSIX_ENSURE_REF(app_protocols);

    POSIX_GUARD(s2n_stuffer_write(out, app_protocols));

    return S2N_SUCCESS;
}

int s2n_server_npn_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    struct s2n_blob *supported_protocols = NULL;
    POSIX_GUARD(s2n_connection_get_protocol_preferences(conn, &supported_protocols));
    POSIX_ENSURE_REF(supported_protocols);

    if (supported_protocols->size == 0) {
        /* No protocols configured */
        return S2N_SUCCESS;
    }

    /* Ignore errors as we can select our own protocol if parsing fails */
    s2n_result_ignore(s2n_select_server_preference_protocol(conn, extension, supported_protocols));

    /*
     *= https://datatracker.ietf.org/doc/id/draft-agl-tls-nextprotoneg-04#section-4
     *# In the event that the client doesn't support any of server's protocols, or
     *# the server doesn't advertise any, it SHOULD select the first protocol
     *# that it supports.
     */
    if (s2n_get_application_protocol(conn) == NULL) {
        struct s2n_stuffer stuffer = { 0 };
        POSIX_GUARD(s2n_stuffer_init(&stuffer, supported_protocols));
        POSIX_GUARD(s2n_stuffer_skip_write(&stuffer, supported_protocols->size));

        uint8_t length = 0;
        POSIX_GUARD(s2n_stuffer_read_uint8(&stuffer, &length));
        POSIX_ENSURE_GT(length, 0);

        uint8_t *data = s2n_stuffer_raw_read(&stuffer, length);
        POSIX_ENSURE_REF(data);

        POSIX_ENSURE_LT((uint16_t)length, sizeof(conn->application_protocol));
        POSIX_CHECKED_MEMCPY(conn->application_protocol, data, length);
        conn->application_protocol[length] = '\0';
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

bool s2n_npn_encrypted_should_send(struct s2n_connection *conn)
{
    return s2n_server_alpn_should_send(conn);
}

S2N_RESULT s2n_calculate_padding(uint8_t protocol_len, uint8_t *padding_len)
{
    RESULT_ENSURE_REF(padding_len);

    /*
     *= https://datatracker.ietf.org/doc/id/draft-agl-tls-nextprotoneg-04#section-3
     *# The length of "padding" SHOULD be 32 - ((len(selected_protocol) + 2) % 32).
     */
    *padding_len = 32 - ((protocol_len + 2) % 32);
    return S2N_RESULT_OK;
}

int s2n_npn_encrypted_extension_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{   
    uint8_t protocol_len = strlen(conn->application_protocol);
    POSIX_GUARD(s2n_stuffer_write_uint8(out, protocol_len));
    POSIX_GUARD(s2n_stuffer_write_bytes(out, (uint8_t*) conn->application_protocol, protocol_len));
    
    uint8_t padding_len = 0;
    POSIX_GUARD_RESULT(s2n_calculate_padding(protocol_len, &padding_len));
    POSIX_GUARD(s2n_stuffer_write_uint8(out, padding_len));
    for (size_t i = 0; i < padding_len; i++) {
        POSIX_GUARD(s2n_stuffer_write_uint8(out, 0));
    }

    return S2N_SUCCESS;
}

int s2n_npn_encrypted_extension_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{   
    uint8_t protocol_len = 0;
    POSIX_GUARD(s2n_stuffer_read_uint8(extension, &protocol_len));
    POSIX_ENSURE_LT((uint16_t)protocol_len, sizeof(conn->application_protocol));

    uint8_t *protocol = s2n_stuffer_raw_read(extension, protocol_len);
    POSIX_ENSURE_REF(protocol);
    POSIX_CHECKED_MEMCPY(conn->application_protocol, protocol, protocol_len);
    conn->application_protocol[protocol_len] = '\0';

    uint8_t expected_padding_len = 0;
    POSIX_GUARD_RESULT(s2n_calculate_padding(protocol_len, &expected_padding_len));
    uint8_t padding_len = 0;
    POSIX_GUARD(s2n_stuffer_read_uint8(extension, &padding_len));
    POSIX_ENSURE_EQ(padding_len, expected_padding_len);

    for (size_t i = 0; i < padding_len; i++) {
        uint8_t byte = 0;
        POSIX_GUARD(s2n_stuffer_read_uint8(extension, &byte));
        POSIX_ENSURE_EQ(byte, 0);
    }
    POSIX_ENSURE_EQ(s2n_stuffer_data_available(extension), 0);

    return S2N_SUCCESS;
}

const s2n_extension_type s2n_npn_encrypted_extension = {
    .iana_value = TLS_EXTENSION_NPN,
    .is_response = true,
    .send = s2n_npn_encrypted_extension_send,
    .recv = s2n_npn_encrypted_extension_recv,
    .should_send = s2n_npn_encrypted_should_send,
    /* The NPN extension is the only one defined for TLS1.2 Encrypted Extensions.
     * If it's missing, something has gone wrong. */
    .if_missing = s2n_extension_error_if_missing,
};
