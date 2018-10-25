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

#include "tls/s2n_server_key_exchange.h"
#include "tls/s2n_client_key_exchange.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_cipher_suites.h"
#include "utils/s2n_safety.h"
#include "s2n_tls.h"

static int get_ecc_extension_size(const struct s2n_connection *conn)
{
    if (s2n_server_can_send_ec_point_formats(conn)){
        return 6;
    } else {
        return 0;
    }
}

static int get_no_extension_size(const struct s2n_connection *conn)
{
    return 0;
}

/* Write the Supported Points Format extension.
 * RFC 4492 section 5.2 states that the absence of this extension in the Server Hello
 * is equivalent to allowing only the uncompressed point format. Let's send the
 * extension in case clients(Openssl 1.0.0) don't honor the implied behavior.
 */
static int write_ecc_extension(const struct s2n_connection *conn, struct s2n_stuffer *out)
{
    if (s2n_server_can_send_ec_point_formats(conn)) {
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
    return 0;
}

static int no_extension(const struct s2n_connection *conn, struct s2n_stuffer *out)
{
    return 0;
}

static int check_dh(const struct s2n_connection *conn)
{
    return conn->config->dhparams != NULL;
}

static int check_ecc(const struct s2n_connection *conn)
{
    return conn->secure.server_ecc_params.negotiated_curve != NULL;
}

const struct s2n_kex s2n_rsa = {
        .is_ephemeral = 0,
        .get_extension_size = &get_no_extension_size,
        .write_server_extensions = &no_extension,
        .server_key_recv = &s2n_rsa_server_recv_key,
        .server_key_send = &s2n_rsa_server_send_key,
        .client_key_recv = &s2n_rsa_client_key_recv,
        .client_key_send = &s2n_rsa_client_key_send,
};

const struct s2n_kex s2n_dhe = {
        .is_ephemeral = 1,
        .get_extension_size = &get_no_extension_size,
        .write_server_extensions = &no_extension,
        .connection_supported = &check_dh,
        .server_key_recv = &s2n_dhe_server_recv_params,
        .server_key_send = &s2n_dhe_server_send_params,
        .client_key_recv = &s2n_dhe_client_key_recv,
        .client_key_send = &s2n_dhe_client_key_send,
};

const struct s2n_kex s2n_ecdhe = {
        .is_ephemeral = 1,
        .get_extension_size = &get_ecc_extension_size,
        .write_server_extensions = &write_ecc_extension,
        .connection_supported = &check_ecc,
        .server_key_recv = &s2n_ecdhe_server_recv_params,
        .server_key_send = &s2n_ecdhe_server_send_params,
        .client_key_recv = &s2n_ecdhe_client_key_recv,
        .client_key_send = &s2n_ecdhe_client_key_send,
};

int s2n_kex_server_extension_size(const struct s2n_kex *kex, struct s2n_connection *conn)
{
    notnull_check(kex->get_extension_size);
    return kex->get_extension_size(conn);
}

int s2n_kex_write_server_extension(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_stuffer *out)
{
    notnull_check(kex->write_server_extensions);
    return kex->write_server_extensions(conn, out);
}

int s2n_kex_supported(const struct s2n_kex *kex, struct s2n_connection *conn)
{
    notnull_check(kex->connection_supported);
    return kex->connection_supported(conn);
}

int s2n_kex_is_ephemeral(const struct s2n_kex *kex)
{
    return kex->is_ephemeral;
}

int s2n_kex_server_key_recv(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *data_to_verify)
{
    notnull_check(kex->server_key_recv);
    return kex->server_key_recv(conn, data_to_verify);
}

int s2n_kex_server_key_send(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *data_to_sign)
{
    notnull_check(kex->server_key_send);
    return kex->server_key_send(conn, data_to_sign);
}

int s2n_kex_client_key_recv(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    notnull_check(kex->client_key_recv);
    return kex->client_key_recv(conn, shared_key);
}

int s2n_kex_client_key_send(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    notnull_check(kex->client_key_send);
    return kex->client_key_send(conn, shared_key);
}
