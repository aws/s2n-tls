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

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdint.h>

#define S2N_MINIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION 2
#define S2N_MAXIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION 3
#define S2N_SSLv2 20
#define S2N_SSLv3 30
#define S2N_TLS10 31
#define S2N_TLS11 32
#define S2N_TLS12 33
#define S2N_UNKNOWN_PROTOCOL_VERSION 0

extern __thread int s2n_errno;

typedef enum {
    S2N_ERR_T_OK=0,
    S2N_ERR_T_IO,
    S2N_ERR_T_CLOSED,
    S2N_ERR_T_BLOCKED,
    S2N_ERR_T_ALERT,
    S2N_ERR_T_PROTO,
    S2N_ERR_T_INTERNAL,
    S2N_ERR_T_USAGE
} s2n_error_type;

extern int s2n_error_get_type(int error);

struct s2n_config;

extern int s2n_init(void);
extern int s2n_cleanup(void);
extern struct s2n_config *s2n_config_new(void);
extern int s2n_config_free(struct s2n_config *config);
extern int s2n_config_free_dhparams(struct s2n_config *config);
extern int s2n_config_free_cert_chain_and_key(struct s2n_config *config);
extern int s2n_config_set_nanoseconds_since_epoch_callback(struct s2n_config *config, int (*nanoseconds_since_epoch)(void *, uint64_t *), void * data);
extern const char *s2n_strerror(int error, const char *lang);

extern int s2n_config_set_cache_store_callback(struct s2n_config *config, int (*cache_store)(void *, uint64_t ttl_in_seconds, const void *key, uint64_t key_size, const void *value, uint64_t value_size), void *data);
extern int s2n_config_set_cache_retrieve_callback(struct s2n_config *config, int (*cache_retrieve)(void *, const void *key, uint64_t key_size, void *value, uint64_t *value_size), void *data);
extern int s2n_config_set_cache_delete_callback(struct s2n_config *config, int (*cache_delete)(void *, const void *key, uint64_t key_size), void *data);

typedef enum {
    S2N_EXTENSION_OCSP_STAPLING = 5,
    S2N_EXTENSION_CERTIFICATE_TRANSPARENCY = 18,
} s2n_tls_extension_type;

extern int s2n_config_add_cert_chain_and_key(struct s2n_config *config, const char *cert_chain_pem, const char *private_key_pem);

extern int s2n_config_add_dhparams(struct s2n_config *config, const char *dhparams_pem);
extern int s2n_config_set_cipher_preferences(struct s2n_config *config, const char *version);
extern int s2n_config_set_protocol_preferences(struct s2n_config *config, const char * const *protocols, int protocol_count);
typedef enum { S2N_STATUS_REQUEST_NONE = 0, S2N_STATUS_REQUEST_OCSP = 1 } s2n_status_request_type;
extern int s2n_config_set_status_request_type(struct s2n_config *config, s2n_status_request_type type);
typedef enum { S2N_CT_SUPPORT_NONE = 0, S2N_CT_SUPPORT_REQUEST = 1 } s2n_ct_support_level;
extern int s2n_config_set_ct_support_level(struct s2n_config *config, s2n_ct_support_level level);
extern int s2n_config_set_extension_data(struct s2n_config *config, s2n_tls_extension_type type, const uint8_t *data, uint32_t length);

struct s2n_connection;
typedef enum { S2N_SERVER, S2N_CLIENT } s2n_mode;
extern struct s2n_connection *s2n_connection_new(s2n_mode mode);
extern int s2n_connection_set_config(struct s2n_connection *conn, struct s2n_config *config);

extern int s2n_connection_set_ctx(struct s2n_connection *conn, void *ctx);
extern void *s2n_connection_get_ctx(struct s2n_connection *conn);

typedef int s2n_client_hello_fn(struct s2n_connection *conn, void *ctx);
extern int s2n_config_set_client_hello_cb(struct s2n_config *config, s2n_client_hello_fn client_hello_callback, void *ctx);

extern int s2n_connection_set_fd(struct s2n_connection *conn, int fd);
extern int s2n_connection_set_read_fd(struct s2n_connection *conn, int readfd);
extern int s2n_connection_set_write_fd(struct s2n_connection *conn, int writefd);
extern int s2n_connection_use_corked_io(struct s2n_connection *conn);

typedef int s2n_recv_fn(void *io_context, uint8_t *buf, uint32_t len);
typedef int s2n_send_fn(void *io_context, const uint8_t *buf, uint32_t len);
extern int s2n_connection_set_recv_ctx(struct s2n_connection *conn, void *ctx);
extern int s2n_connection_set_send_ctx(struct s2n_connection *conn, void *ctx);
extern int s2n_connection_set_recv_cb(struct s2n_connection *conn, s2n_recv_fn recv);
extern int s2n_connection_set_send_cb(struct s2n_connection *conn, s2n_send_fn send);

extern int s2n_connection_prefer_throughput(struct s2n_connection *conn);
extern int s2n_connection_prefer_low_latency(struct s2n_connection *conn);

typedef enum { S2N_BUILT_IN_BLINDING, S2N_SELF_SERVICE_BLINDING } s2n_blinding;
extern int s2n_connection_set_blinding(struct s2n_connection *conn, s2n_blinding blinding);
extern uint64_t s2n_connection_get_delay(struct s2n_connection *conn);

extern int s2n_set_server_name(struct s2n_connection *conn, const char *server_name);
extern const char *s2n_get_server_name(struct s2n_connection *conn);
extern const char *s2n_get_application_protocol(struct s2n_connection *conn);
extern const uint8_t *s2n_connection_get_ocsp_response(struct s2n_connection *conn, uint32_t *length);
extern const uint8_t *s2n_connection_get_sct_list(struct s2n_connection *conn, uint32_t *length);

typedef enum { S2N_NOT_BLOCKED = 0, S2N_BLOCKED_ON_READ, S2N_BLOCKED_ON_WRITE } s2n_blocked_status;
extern int s2n_negotiate(struct s2n_connection *conn, s2n_blocked_status *blocked);
extern ssize_t s2n_send(struct s2n_connection *conn, const void *buf, ssize_t size, s2n_blocked_status *blocked);
extern ssize_t s2n_recv(struct s2n_connection *conn,  void *buf, ssize_t size, s2n_blocked_status *blocked);

extern int s2n_connection_wipe(struct s2n_connection *conn);
extern int s2n_connection_free(struct s2n_connection *conn);
extern int s2n_shutdown(struct s2n_connection *conn, s2n_blocked_status *blocked);

extern uint64_t s2n_connection_get_wire_bytes_in(struct s2n_connection *conn);
extern uint64_t s2n_connection_get_wire_bytes_out(struct s2n_connection *conn);
extern int s2n_connection_get_client_protocol_version(struct s2n_connection *conn);
extern int s2n_connection_get_server_protocol_version(struct s2n_connection *conn);
extern int s2n_connection_get_actual_protocol_version(struct s2n_connection *conn);
extern int s2n_connection_get_client_hello_version(struct s2n_connection *conn);
extern const char *s2n_connection_get_cipher(struct s2n_connection *conn);
extern const char *s2n_connection_get_curve(struct s2n_connection *conn);
extern int s2n_connection_get_alert(struct s2n_connection *conn);

#ifdef __cplusplus
}
#endif
