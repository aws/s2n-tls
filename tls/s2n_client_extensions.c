/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdint.h>
#include <string.h>

#include "error/s2n_errno.h"

#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_connection.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

static int s2n_alpn_mutual_protocol(struct s2n_connection *conn);

int s2n_client_extensions_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    uint16_t total_size = 0;

    /* Signature algorithms */
    if (conn->actual_protocol_version == S2N_TLS12) {
        total_size += 8;
    }

    uint16_t application_protocols_len = conn->config->application_protocols.size;
    uint16_t server_name_len = strlen(conn->server_name);

    if (server_name_len) {
        total_size += 9 + server_name_len;
    }
    if (application_protocols_len) {
        total_size += 6 + application_protocols_len;
    }
    if (conn->config->status_request_type != S2N_STATUS_REQUEST_NONE) {
        total_size += 9;
    }

    GUARD(s2n_stuffer_write_uint16(out, total_size));

    if (conn->actual_protocol_version == S2N_TLS12) {
        /* The extension header */
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SIGNATURE_ALGORITHMS));
        GUARD(s2n_stuffer_write_uint16(out, 4));

        /* Just one signature/hash pair, so 2 bytes */
        GUARD(s2n_stuffer_write_uint16(out, 2));
        GUARD(s2n_stuffer_write_uint8(out, TLS_SIGNATURE_ALGORITHM_SHA1));
        GUARD(s2n_stuffer_write_uint8(out, TLS_SIGNATURE_ALGORITHM_RSA));
    }

    if (server_name_len) {
        /* Write the server name */
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SERVER_NAME));
        GUARD(s2n_stuffer_write_uint16(out, server_name_len + 5));

        /* Size of all of the server names */
        GUARD(s2n_stuffer_write_uint16(out, server_name_len + 3));

        /* Name type - host name, RFC3546 */
        GUARD(s2n_stuffer_write_uint8(out, 0));

        struct s2n_blob server_name;
        server_name.data = (uint8_t *) conn->server_name;
        server_name.size = server_name_len;
        GUARD(s2n_stuffer_write_uint16(out, server_name_len));
        GUARD(s2n_stuffer_write(out, &server_name));
    }

    /* Write ALPN extension */
    if (application_protocols_len) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_ALPN));
        GUARD(s2n_stuffer_write_uint16(out, application_protocols_len + 2));
        GUARD(s2n_stuffer_write_uint16(out, application_protocols_len));
        GUARD(s2n_stuffer_write(out, &conn->config->application_protocols));
    }

    if (conn->config->status_request_type != S2N_STATUS_REQUEST_NONE) {
        /* We only support OCSP */
        eq_check(conn->config->status_request_type, S2N_STATUS_REQUEST_OCSP);
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_STATUS_REQUEST));
        GUARD(s2n_stuffer_write_uint16(out, 5));
        GUARD(s2n_stuffer_write_uint8(out, (uint8_t)conn->config->status_request_type));
        GUARD(s2n_stuffer_write_uint16(out, 0));
        GUARD(s2n_stuffer_write_uint16(out, 0));
    }

    return 0;
}

int s2n_client_extensions_recv(struct s2n_connection *conn, struct s2n_blob *extensions)
{
    struct s2n_stuffer in;

    GUARD(s2n_stuffer_init(&in, extensions));
    GUARD(s2n_stuffer_write(&in, extensions));

    while (s2n_stuffer_data_available(&in)) {
        struct s2n_blob ext;
        uint16_t extension_type, extension_size;
        struct s2n_stuffer extension;

        GUARD(s2n_stuffer_read_uint16(&in, &extension_type));
        GUARD(s2n_stuffer_read_uint16(&in, &extension_size));

        ext.size = extension_size;
        lte_check(extension_size, s2n_stuffer_data_available(&in));
        ext.data = s2n_stuffer_raw_read(&in, ext.size);
        notnull_check(ext.data);

        GUARD(s2n_stuffer_init(&extension, &ext));
        GUARD(s2n_stuffer_write(&extension, &ext));

        switch (extension_type) {
            int found_sha1_rsa;
            uint16_t size_of_all;

        case TLS_EXTENSION_SERVER_NAME:
            GUARD(s2n_stuffer_read_uint16(&extension, &size_of_all));
            if (size_of_all > s2n_stuffer_data_available(&extension) || size_of_all < 3) {
                continue;
            }

            uint8_t server_name_type;
            GUARD(s2n_stuffer_read_uint8(&extension, &server_name_type));
            if (server_name_type != 0) {
                continue;
            }

            uint16_t server_name_len;
            GUARD(s2n_stuffer_read_uint16(&extension, &server_name_len));
            if (server_name_len + 3 > size_of_all) {
                continue;
            }

            if (server_name_len > sizeof(conn->server_name) - 1) {
                continue;
            }

            uint8_t *server_name = s2n_stuffer_raw_read(&extension, server_name_len);
            notnull_check(server_name);

            /* copy the first server name */
            memcpy_check(conn->server_name, server_name, server_name_len);
            break;

        case TLS_EXTENSION_SIGNATURE_ALGORITHMS:
            found_sha1_rsa = 0;

            uint16_t length_of_all_pairs;
            GUARD(s2n_stuffer_read_uint16(&extension, &length_of_all_pairs));
            if (length_of_all_pairs > s2n_stuffer_data_available(&extension)) {
                continue;
            }

            /* Pairs occur in two byte lengths */
            if (length_of_all_pairs % 2 || s2n_stuffer_data_available(&extension) % 2) {
                continue;
            }

            while (s2n_stuffer_data_available(&extension)) {
                uint8_t hash_alg;
                uint8_t sig_alg;

                GUARD(s2n_stuffer_read_uint8(&extension, &hash_alg));
                GUARD(s2n_stuffer_read_uint8(&extension, &sig_alg));

                if (hash_alg == TLS_SIGNATURE_ALGORITHM_SHA1 && sig_alg == TLS_SIGNATURE_ALGORITHM_RSA) {
                    found_sha1_rsa = 1;
                    break;
                }
            }

            if (found_sha1_rsa == 0) {
                S2N_ERROR(S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
            }
            break;
        case TLS_EXTENSION_ALPN:
            GUARD(s2n_stuffer_read_uint16(&extension, &size_of_all));
            if (size_of_all > s2n_stuffer_data_available(&extension) || size_of_all < 3) {
                continue;
            }

            GUARD(s2n_alloc(&conn->application_protocols, size_of_all));

            GUARD(s2n_stuffer_read(&extension, &conn->application_protocols));

            GUARD(s2n_alpn_mutual_protocol(conn));

            break;
        case TLS_EXTENSION_STATUS_REQUEST:
            break;
        }
    }

    return 0;
}

int s2n_alpn_mutual_protocol(struct s2n_connection *conn)
{
    if (!conn->config->application_protocols.size) {
        return 0;
    }

    struct s2n_stuffer client_protos;
    struct s2n_stuffer server_protos;
    GUARD(s2n_stuffer_init(&client_protos, &conn->application_protocols));
    GUARD(s2n_stuffer_write(&client_protos, &conn->application_protocols));
    GUARD(s2n_stuffer_init(&server_protos, &conn->config->application_protocols));
    GUARD(s2n_stuffer_write(&server_protos, &conn->config->application_protocols));

    while (s2n_stuffer_data_available(&server_protos)) {
        uint8_t length;
        uint8_t protocol[255];
        GUARD(s2n_stuffer_read_uint8(&server_protos, &length));
        GUARD(s2n_stuffer_read_bytes(&server_protos, protocol, length));
        
        while (s2n_stuffer_data_available(&client_protos)) {
            uint8_t client_length;
            uint8_t client_protocol[255];
            GUARD(s2n_stuffer_read_uint8(&client_protos, &client_length));
            if (client_length > s2n_stuffer_data_available(&client_protos)) {
                S2N_ERROR(S2N_ERR_BAD_MESSAGE);
            }
            if (client_length != length) {
                GUARD(s2n_stuffer_skip_read(&client_protos, client_length));
            }
            GUARD(s2n_stuffer_read_bytes(&client_protos, client_protocol, client_length));
            if (memcmp(client_protocol, protocol, client_length) == 0) {
                memcpy_check(conn->application_protocol, client_protocol, client_length);
                conn->application_protocol[client_length] = '\0';
                return 0;
            }
        }

        GUARD(s2n_stuffer_reread(&client_protos));
    }

    S2N_ERROR(S2N_ERR_NO_APPLICATION_PROTOCOL);
}

