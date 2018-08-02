/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "tls/s2n_tls.h"
#include "tls/s2n_cipher_suites.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

static int s2n_recv_server_alpn(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_server_status_request(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_server_sct_list(struct s2n_connection *conn, struct s2n_stuffer *extension);
static int s2n_recv_server_max_frag_len(struct s2n_connection *conn, struct s2n_stuffer *extension);

int s2n_server_extensions_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    uint16_t total_size = 0;

    uint8_t application_protocol_len = strlen(conn->application_protocol);

    if (application_protocol_len) {
        total_size += 7 + application_protocol_len;
    }
    if (s2n_server_can_send_ocsp(conn)) {
        total_size += 4;
    }
    if (conn->secure_renegotiation) {
        total_size += 5;
    }
    if (conn->secure.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC) {
        total_size += 6;
    }
    if (s2n_server_can_send_sct_list(conn)) {
        total_size += 4 + conn->config->cert_and_key_pairs->sct_list.size;
    }
    if (conn->mfl_code) {
        total_size += 5;
    }

    if (total_size == 0) {
        return 0;
    }

    GUARD(s2n_stuffer_write_uint16(out, total_size));

    /* Write the Supported Points Format extension.
     * RFC 4492 section 5.2 states that the absence of this extension in the Server Hello
     * is equivalent to allowing only the uncompressed point format. Let's send the
     * extension in case clients(Openssl 1.0.0) don't honor the implied behavior.
     */
    if (conn->secure.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC)  {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_EC_POINT_FORMATS));
        /* Total extension length */
        GUARD(s2n_stuffer_write_uint16(out, 2));
        /* Format list length */
        GUARD(s2n_stuffer_write_uint8(out, 1));
        /* Only uncompressed format is supported. Interoperability shouldn't be an issue:
         * RFC 4492 Section 5.1.2: Implementations must support it for all of their curves.
         */
        GUARD(s2n_stuffer_write_uint8(out, TLS_EC_FORMAT_UNCOMPRESSED));
    }

    /* Write the renegotiation_info extension */
    if (conn->secure_renegotiation) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_RENEGOTIATION_INFO));
        /* renegotiation_info length */
        GUARD(s2n_stuffer_write_uint16(out, 1));
        /* renegotiated_connection length. Zero since we don't support renegotiation. */
        GUARD(s2n_stuffer_write_uint8(out, 0));
    }

    /* Write ALPN extension */
    if (application_protocol_len) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_ALPN));
        GUARD(s2n_stuffer_write_uint16(out, application_protocol_len + 3));
        GUARD(s2n_stuffer_write_uint16(out, application_protocol_len + 1));
        GUARD(s2n_stuffer_write_uint8(out, application_protocol_len));
        GUARD(s2n_stuffer_write_bytes(out, (uint8_t *) conn->application_protocol, application_protocol_len));
    }

    /* Write OCSP extension */
    if (s2n_server_can_send_ocsp(conn)) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_STATUS_REQUEST));
        GUARD(s2n_stuffer_write_uint16(out, 0));
    }

    /* Write Signed Certificate Timestamp extension */
    if (s2n_server_can_send_sct_list(conn)) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SCT_LIST));
        GUARD(s2n_stuffer_write_uint16(out, conn->config->cert_and_key_pairs->sct_list.size));
        GUARD(s2n_stuffer_write_bytes(out, conn->config->cert_and_key_pairs->sct_list.data,
                                      conn->config->cert_and_key_pairs->sct_list.size));
    }

    if (conn->mfl_code) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_MAX_FRAG_LEN));
        GUARD(s2n_stuffer_write_uint16(out, sizeof(uint8_t)));
        GUARD(s2n_stuffer_write_uint8(out, conn->mfl_code));
    }

    return 0;
}

int s2n_server_extensions_recv(struct s2n_connection *conn, struct s2n_blob *extensions)
{
    struct s2n_stuffer in = {{0}};

    GUARD(s2n_stuffer_init(&in, extensions));
    GUARD(s2n_stuffer_write(&in, extensions));

    while (s2n_stuffer_data_available(&in)) {
        struct s2n_blob ext = {0};
        uint16_t extension_type, extension_size;
        struct s2n_stuffer extension = {{0}};

        GUARD(s2n_stuffer_read_uint16(&in, &extension_type));
        GUARD(s2n_stuffer_read_uint16(&in, &extension_size));

        ext.size = extension_size;
        ext.data = s2n_stuffer_raw_read(&in, ext.size);
        notnull_check(ext.data);

        GUARD(s2n_stuffer_init(&extension, &ext));
        GUARD(s2n_stuffer_write(&extension, &ext));

        switch (extension_type) {
        case TLS_EXTENSION_ALPN:
            GUARD(s2n_recv_server_alpn(conn, &extension));
            break;
        case TLS_EXTENSION_STATUS_REQUEST:
            GUARD(s2n_recv_server_status_request(conn, &extension));
            break;
        case TLS_EXTENSION_SCT_LIST:
            GUARD(s2n_recv_server_sct_list(conn, &extension));
            break;
        case TLS_EXTENSION_MAX_FRAG_LEN:
            GUARD(s2n_recv_server_max_frag_len(conn, &extension));
            break;
        }
    }

    return 0;
}

int s2n_recv_server_alpn(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint16_t size_of_all;
    GUARD(s2n_stuffer_read_uint16(extension, &size_of_all));
    if (size_of_all > s2n_stuffer_data_available(extension) || size_of_all < 3) {
        /* ignore invalid extension size */
        return 0;
    }

    uint8_t protocol_len;
    GUARD(s2n_stuffer_read_uint8(extension, &protocol_len));

    uint8_t *protocol = s2n_stuffer_raw_read(extension, protocol_len);
    notnull_check(protocol);

    /* copy the first protocol name */
    memcpy_check(conn->application_protocol, protocol, protocol_len);
    conn->application_protocol[protocol_len] = '\0';

    return 0;
}

int s2n_recv_server_status_request(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    conn->status_type = S2N_STATUS_REQUEST_OCSP;

    return 0;
}

int s2n_recv_server_sct_list(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    struct s2n_blob sct_list = { .data = NULL, .size = 0 };

    sct_list.size = s2n_stuffer_data_available(extension);
    sct_list.data = s2n_stuffer_raw_read(extension, sct_list.size);
    notnull_check(sct_list.data);

    GUARD(s2n_dup(&sct_list, &conn->ct_response));

    return 0;
}

int s2n_recv_server_max_frag_len(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint8_t mfl_code;
    GUARD(s2n_stuffer_read_uint8(extension, &mfl_code));
    S2N_ERROR_IF(mfl_code != conn->config->mfl_code, S2N_ERR_MAX_FRAG_LEN_MISMATCH);

    return 0;
}
