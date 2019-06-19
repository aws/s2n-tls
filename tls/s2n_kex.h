/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#pragma once

#include <stdint.h>
#include "tls/s2n_connection.h"
#include "tls/s2n_kex_data.h"

struct s2n_kex {
    uint8_t is_ephemeral;
    const struct s2n_kex *hybrid[2];

    int (*get_server_extension_size)(const struct s2n_connection *conn);
    int (*write_server_extensions)(const struct s2n_connection *conn, struct s2n_stuffer *out);
    int (*connection_supported)(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn);
    int (*configure_connection)(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn);
    int (*server_key_recv_read_data)(struct s2n_connection *conn, struct s2n_blob *data_to_verify, struct s2n_kex_raw_server_data *kex_data);
    int (*server_key_recv_parse_data)(struct s2n_connection *conn, struct s2n_kex_raw_server_data *kex_data);
    int (*server_key_send)(struct s2n_connection *conn, struct s2n_blob *data_to_sign);
    int (*client_key_recv)(struct s2n_connection *conn, struct s2n_blob *shared_key);
    int (*client_key_send)(struct s2n_connection *conn, struct s2n_blob *shared_key);
    int (*prf)(struct s2n_connection *conn, struct s2n_blob *premaster_secret);
};

extern const struct s2n_kex s2n_rsa;
extern const struct s2n_kex s2n_dhe;
extern const struct s2n_kex s2n_ecdhe;
extern const struct s2n_kex s2n_hybrid_ecdhe_kem;

extern int s2n_kex_server_extension_size(const struct s2n_kex *kex, const struct s2n_connection *conn);
extern int s2n_kex_write_server_extension(const struct s2n_kex *kex, const struct s2n_connection *conn, struct s2n_stuffer *out);
extern int s2n_kex_supported(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn);
extern int s2n_configure_kex(const struct s2n_cipher_suite *cipher_suite, struct s2n_connection *conn);
extern int s2n_kex_is_ephemeral(const struct s2n_kex *kex);

extern int s2n_kex_server_key_recv_read_data(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *data_to_verify,
        struct s2n_kex_raw_server_data *raw_server_data);
extern int s2n_kex_server_key_recv_parse_data(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_kex_raw_server_data *raw_server_data);
extern int s2n_kex_server_key_send(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *data_to_sign);
extern int s2n_kex_client_key_recv(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key);
extern int s2n_kex_client_key_send(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key);

extern int s2n_kex_tls_prf(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *premaster_secret);
