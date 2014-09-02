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

#pragma once

#include <stdint.h>

#define S2N_SSLv3 30
#define S2N_TLS10 31
#define S2N_TLS11 32
#define S2N_TLS12 33

struct s2n_config;

extern int s2n_init(const char **err);
extern int s2n_cleanup(const char **err);
extern struct s2n_config *s2n_config_new(const char **err);
extern int s2n_config_free(struct s2n_config *config, const char **err);

extern int s2n_config_add_cert_chain_and_key(struct s2n_config *config, char *cert_chain_pem, char *private_key_pem, const char **err);
extern int s2n_config_add_dhparams(struct s2n_config *config, char *dhparams_pem, const char **err);
extern int s2n_config_set_cipher_preferences(struct s2n_config *config, const char *preferences, const char **err);
extern int s2n_config_set_key_exchange_preferences(struct s2n_config *config, const char *preferences, const char **err);

struct s2n_connection;
typedef enum { S2N_SERVER, S2N_CLIENT } s2n_mode;
typedef enum { S2N_OK, S2N_NEEDS_READ, S2N_NEEDS_WRITE } s2n_status;
extern struct s2n_connection *s2n_connection_new(s2n_mode mode, const char **err);
extern int s2n_connection_set_config(struct s2n_connection *conn, struct s2n_config *config, const char **err);

extern int s2n_connection_set_fd(struct s2n_connection *conn, int readfd, const char **err);
extern int s2n_connection_set_read_fd(struct s2n_connection *conn, int readfd, const char **err);
extern int s2n_connection_set_write_fd(struct s2n_connection *conn, int readfd, const char **err);

extern int s2n_set_server_name(struct s2n_connection *conn, const char *server_name, const char **err);
extern const char *s2n_get_server_name(struct s2n_connection *conn, const char **err);

extern int s2n_negotiate(struct s2n_connection *conn, int *more, const char **err);
extern int s2n_send(struct s2n_connection *conn, void *buf, uint32_t size, int *more, const char **err);
extern int s2n_recv(struct s2n_connection *conn,  void *buf, uint32_t size, int *more, const char **err);
extern int s2n_shutdown(struct s2n_connection *conn, int *more, const char **err);

extern int s2n_connection_wipe(struct s2n_connection *conn, const char **err);
extern int s2n_connection_free(struct s2n_connection *conn, const char **err);

extern s2n_status s2n_connection_get_status(struct s2n_connection *conn);
extern uint64_t s2n_connection_get_wire_bytes_in(struct s2n_connection *conn);
extern uint64_t s2n_connection_get_wire_bytes_out(struct s2n_connection *conn);
extern int s2n_connection_get_client_protocol_version(struct s2n_connection *conn, const char **err);
extern int s2n_connection_get_server_protocol_version(struct s2n_connection *conn, const char **err);
extern int s2n_connection_get_actual_protocol_version(struct s2n_connection *conn, const char **err);
extern int s2n_connection_was_client_hello_sslv2(struct s2n_connection *conn);
extern const char *s2n_connection_get_cipher(struct s2n_connection *conn, const char **err);
extern int s2n_connection_get_alert(struct s2n_connection *conn, const char **err);
