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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/ossl_typ.h>
#include <sys/uio.h>

/* Function return code  */
#define S2N_SUCCESS 0
#define S2N_FAILURE -1

#define S2N_MINIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION 2
#define S2N_MAXIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION 3
#define S2N_SSLv2 20
#define S2N_SSLv3 30
#define S2N_TLS10 31
#define S2N_TLS11 32
#define S2N_TLS12 33
#define S2N_TLS13 34
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
struct s2n_connection;

extern unsigned long s2n_get_openssl_version(void);
extern int s2n_init(void);
extern int s2n_cleanup(void);
extern struct s2n_config *s2n_config_new(void);
extern int s2n_config_free(struct s2n_config *config);
extern int s2n_config_free_dhparams(struct s2n_config *config);
extern int s2n_config_free_cert_chain_and_key(struct s2n_config *config);

typedef int (*s2n_clock_time_nanoseconds) (void *, uint64_t *);
typedef int (*s2n_cache_retrieve_callback) (struct s2n_connection *conn, void *, const void *key, uint64_t key_size, void *value, uint64_t *value_size);
typedef int (*s2n_cache_store_callback) (struct s2n_connection *conn, void *, uint64_t ttl_in_seconds, const void *key, uint64_t key_size, const void *value, uint64_t value_size);
typedef int (*s2n_cache_delete_callback) (struct s2n_connection *conn,  void *, const void *key, uint64_t key_size);

extern int s2n_config_set_wall_clock(struct s2n_config *config, s2n_clock_time_nanoseconds clock_fn, void *ctx);
extern int s2n_config_set_monotonic_clock(struct s2n_config *config, s2n_clock_time_nanoseconds clock_fn, void *ctx);

extern const char *s2n_strerror(int error, const char *lang);
extern const char *s2n_strerror_debug(int error, const char *lang);
extern const char *s2n_strerror_name(int error); 


struct s2n_stacktrace;
extern bool s2n_stack_traces_enabled(void);
extern int s2n_stack_traces_enabled_set(bool newval);
extern int s2n_calculate_stacktrace(void);
extern int s2n_print_stacktrace(FILE *fptr);
extern int s2n_free_stacktrace(void);
extern int s2n_get_stacktrace(struct s2n_stacktrace *trace);

extern int s2n_config_set_cache_store_callback(struct s2n_config *config, s2n_cache_store_callback cache_store_callback, void *data);
extern int s2n_config_set_cache_retrieve_callback(struct s2n_config *config, s2n_cache_retrieve_callback cache_retrieve_callback, void *data);
extern int s2n_config_set_cache_delete_callback(struct s2n_config *config, s2n_cache_delete_callback cache_delete_callback, void *data);

typedef enum {
    S2N_EXTENSION_SERVER_NAME = 0,
    S2N_EXTENSION_MAX_FRAG_LEN = 1,
    S2N_EXTENSION_OCSP_STAPLING = 5,
    S2N_EXTENSION_SUPPORTED_GROUPS = 10,
    S2N_EXTENSION_EC_POINT_FORMATS = 11,
    S2N_EXTENSION_SIGNATURE_ALGORITHMS = 13,
    S2N_EXTENSION_ALPN = 16,
    S2N_EXTENSION_CERTIFICATE_TRANSPARENCY = 18,
    S2N_EXTENSION_RENEGOTIATION_INFO = 65281,
} s2n_tls_extension_type;

typedef enum {
    S2N_TLS_MAX_FRAG_LEN_512 = 1,
    S2N_TLS_MAX_FRAG_LEN_1024 = 2,
    S2N_TLS_MAX_FRAG_LEN_2048 = 3,
    S2N_TLS_MAX_FRAG_LEN_4096 = 4,
} s2n_max_frag_len;

struct s2n_cert_chain_and_key;
extern struct s2n_cert_chain_and_key *s2n_cert_chain_and_key_new(void);
extern int s2n_cert_chain_and_key_load_pem(struct s2n_cert_chain_and_key *chain_and_key, const char *chain_pem, const char *private_key_pem);
extern int s2n_cert_chain_and_key_free(struct s2n_cert_chain_and_key *cert_and_key);
extern int s2n_cert_chain_and_key_set_ctx(struct s2n_cert_chain_and_key *cert_and_key, void *ctx);
extern void *s2n_cert_chain_and_key_get_ctx(struct s2n_cert_chain_and_key *cert_and_key);

typedef struct s2n_cert_chain_and_key* (*s2n_cert_tiebreak_callback) (struct s2n_cert_chain_and_key *cert1, struct s2n_cert_chain_and_key *cert2, uint8_t *name, uint32_t name_len);
extern int s2n_config_set_cert_tiebreak_callback(struct s2n_config *config, s2n_cert_tiebreak_callback cert_tiebreak_cb);

extern int s2n_config_add_cert_chain_and_key(struct s2n_config *config, const char *cert_chain_pem, const char *private_key_pem);
extern int s2n_config_add_cert_chain_and_key_to_store(struct s2n_config *config, struct s2n_cert_chain_and_key *cert_key_pair);
extern int s2n_config_set_cert_chain_and_key_defaults(struct s2n_config *config,
                                                      struct s2n_cert_chain_and_key **cert_key_pairs,
                                                      uint32_t num_cert_key_pairs);

extern int s2n_config_set_verification_ca_location(struct s2n_config *config, const char *ca_pem_filename, const char *ca_dir);
extern int s2n_config_add_pem_to_trust_store(struct s2n_config *config, const char *pem);

typedef uint8_t (*s2n_verify_host_fn) (const char *host_name, size_t host_name_len, void *data);
/* will be inherited by s2n_connection. If s2n_connection specifies a callback, that callback will be used for that connection. */
extern int s2n_config_set_verify_host_callback(struct s2n_config *config, s2n_verify_host_fn, void *data);

extern int s2n_config_set_check_stapled_ocsp_response(struct s2n_config *config, uint8_t check_ocsp);
extern int s2n_config_disable_x509_verification(struct s2n_config *config);
extern int s2n_config_set_max_cert_chain_depth(struct s2n_config *config, uint16_t max_depth);

extern int s2n_config_add_dhparams(struct s2n_config *config, const char *dhparams_pem);
extern int s2n_config_set_cipher_preferences(struct s2n_config *config, const char *version);
extern int s2n_config_set_protocol_preferences(struct s2n_config *config, const char * const *protocols, int protocol_count);
typedef enum { S2N_STATUS_REQUEST_NONE = 0, S2N_STATUS_REQUEST_OCSP = 1 } s2n_status_request_type;
extern int s2n_config_set_status_request_type(struct s2n_config *config, s2n_status_request_type type);
typedef enum { S2N_CT_SUPPORT_NONE = 0, S2N_CT_SUPPORT_REQUEST = 1 } s2n_ct_support_level;
extern int s2n_config_set_ct_support_level(struct s2n_config *config, s2n_ct_support_level level);
typedef enum { S2N_ALERT_FAIL_ON_WARNINGS = 0, S2N_ALERT_IGNORE_WARNINGS = 1 } s2n_alert_behavior;
extern int s2n_config_set_alert_behavior(struct s2n_config *config, s2n_alert_behavior alert_behavior);
extern int s2n_config_set_extension_data(struct s2n_config *config, s2n_tls_extension_type type, const uint8_t *data, uint32_t length);
extern int s2n_config_send_max_fragment_length(struct s2n_config *config, s2n_max_frag_len mfl_code);
extern int s2n_config_accept_max_fragment_length(struct s2n_config *config);

extern int s2n_config_set_session_state_lifetime(struct s2n_config *config, uint64_t lifetime_in_secs);

extern int s2n_config_set_session_tickets_onoff(struct s2n_config *config, uint8_t enabled);
extern int s2n_config_set_ticket_encrypt_decrypt_key_lifetime(struct s2n_config *config, uint64_t lifetime_in_secs);
extern int s2n_config_set_ticket_decrypt_key_lifetime(struct s2n_config *config, uint64_t lifetime_in_secs);
extern int s2n_config_add_ticket_crypto_key(struct s2n_config *config,
                                            const uint8_t *name, uint32_t name_len,
                                            uint8_t *key, uint32_t key_len,
                                            uint64_t intro_time_in_seconds_from_epoch);

typedef enum { S2N_SERVER, S2N_CLIENT } s2n_mode;
extern struct s2n_connection *s2n_connection_new(s2n_mode mode);
extern int s2n_connection_set_config(struct s2n_connection *conn, struct s2n_config *config);

extern int s2n_connection_set_ctx(struct s2n_connection *conn, void *ctx);
extern void *s2n_connection_get_ctx(struct s2n_connection *conn);

typedef int s2n_client_hello_fn(struct s2n_connection *conn, void *ctx);
extern int s2n_config_set_client_hello_cb(struct s2n_config *config, s2n_client_hello_fn client_hello_callback, void *ctx);

struct s2n_client_hello;
extern struct s2n_client_hello *s2n_connection_get_client_hello(struct s2n_connection *conn);
extern ssize_t s2n_client_hello_get_raw_message_length(struct s2n_client_hello *ch);
extern ssize_t s2n_client_hello_get_raw_message(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length);
extern ssize_t s2n_client_hello_get_cipher_suites_length(struct s2n_client_hello *ch);
extern ssize_t s2n_client_hello_get_cipher_suites(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length);
extern ssize_t s2n_client_hello_get_extensions_length(struct s2n_client_hello *ch);
extern ssize_t s2n_client_hello_get_extensions(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length);
extern ssize_t s2n_client_hello_get_extension_length(struct s2n_client_hello *ch, s2n_tls_extension_type extension_type);
extern ssize_t s2n_client_hello_get_extension_by_id(struct s2n_client_hello *ch, s2n_tls_extension_type extension_type, uint8_t *out, uint32_t max_length);

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
extern int s2n_connection_set_dynamic_record_threshold(struct s2n_connection *conn, uint32_t resize_threshold, uint16_t timeout_threshold);

/* If you don't want to use the configuration wide callback, you can set this per connection and it will be honored. */
extern int s2n_connection_set_verify_host_callback(struct s2n_connection *config, s2n_verify_host_fn host_fn, void *data);

typedef enum { S2N_BUILT_IN_BLINDING, S2N_SELF_SERVICE_BLINDING } s2n_blinding;
extern int s2n_connection_set_blinding(struct s2n_connection *conn, s2n_blinding blinding);
extern uint64_t s2n_connection_get_delay(struct s2n_connection *conn);

extern int s2n_connection_set_cipher_preferences(struct s2n_connection *conn, const char *version);
extern int s2n_connection_set_protocol_preferences(struct s2n_connection *conn, const char * const *protocols, int protocol_count);
extern int s2n_set_server_name(struct s2n_connection *conn, const char *server_name);
extern const char *s2n_get_server_name(struct s2n_connection *conn);
extern const char *s2n_get_application_protocol(struct s2n_connection *conn);
extern const uint8_t *s2n_connection_get_ocsp_response(struct s2n_connection *conn, uint32_t *length);
extern const uint8_t *s2n_connection_get_sct_list(struct s2n_connection *conn, uint32_t *length);

typedef enum { S2N_NOT_BLOCKED = 0, S2N_BLOCKED_ON_READ, S2N_BLOCKED_ON_WRITE, S2N_BLOCKED_ON_APPLICATION_INPUT } s2n_blocked_status;
extern int s2n_negotiate(struct s2n_connection *conn, s2n_blocked_status *blocked);
extern ssize_t s2n_send(struct s2n_connection *conn, const void *buf, ssize_t size, s2n_blocked_status *blocked);
extern ssize_t s2n_sendv(struct s2n_connection *conn, const struct iovec *bufs, ssize_t count, s2n_blocked_status *blocked);
extern ssize_t s2n_sendv_with_offset(struct s2n_connection *conn, const struct iovec *bufs, ssize_t count, ssize_t offs, s2n_blocked_status *blocked);
extern ssize_t s2n_recv(struct s2n_connection *conn,  void *buf, ssize_t size, s2n_blocked_status *blocked);
extern uint32_t s2n_peek(struct s2n_connection *conn);

extern int s2n_connection_free_handshake(struct s2n_connection *conn);
extern int s2n_connection_release_buffers(struct s2n_connection *conn);
extern int s2n_connection_wipe(struct s2n_connection *conn);
extern int s2n_connection_free(struct s2n_connection *conn);
extern int s2n_shutdown(struct s2n_connection *conn, s2n_blocked_status *blocked);

typedef enum { S2N_CERT_AUTH_NONE, S2N_CERT_AUTH_REQUIRED, S2N_CERT_AUTH_OPTIONAL } s2n_cert_auth_type;

extern int s2n_config_get_client_auth_type(struct s2n_config *config, s2n_cert_auth_type *client_auth_type);
extern int s2n_config_set_client_auth_type(struct s2n_config *config, s2n_cert_auth_type client_auth_type);
extern int s2n_connection_get_client_auth_type(struct s2n_connection *conn, s2n_cert_auth_type *client_auth_type);
extern int s2n_connection_set_client_auth_type(struct s2n_connection *conn, s2n_cert_auth_type client_auth_type);
extern int s2n_connection_get_client_cert_chain(struct s2n_connection *conn, uint8_t **der_cert_chain_out, uint32_t *cert_chain_len);

extern int s2n_connection_set_session(struct s2n_connection *conn, const uint8_t *session, size_t length);
extern int s2n_connection_get_session(struct s2n_connection *conn, uint8_t *session, size_t max_length);
extern int s2n_connection_get_session_ticket_lifetime_hint(struct s2n_connection *conn);
extern int s2n_connection_get_session_length(struct s2n_connection *conn);
extern int s2n_connection_get_session_id_length(struct s2n_connection *conn);
extern int s2n_connection_get_session_id(struct s2n_connection *conn, uint8_t *session_id, size_t max_length);
extern int s2n_connection_is_session_resumed(struct s2n_connection *conn);
extern int s2n_connection_is_ocsp_stapled(struct s2n_connection *conn);

extern struct s2n_cert_chain_and_key *s2n_connection_get_selected_cert(struct s2n_connection *conn);

/* RFC's that define below values:
 *  - https://tools.ietf.org/html/rfc5246#section-7.4.4
 *  - https://tools.ietf.org/search/rfc4492#section-5.5
 */
typedef enum {
    S2N_CERT_TYPE_RSA_SIGN = 1,
    S2N_CERT_TYPE_DSS_SIGN = 2,
    S2N_CERT_TYPE_RSA_FIXED_DH = 3,
    S2N_CERT_TYPE_DSS_FIXED_DH = 4,
    S2N_CERT_TYPE_RSA_EPHEMERAL_DH_RESERVED = 5,
    S2N_CERT_TYPE_DSS_EPHEMERAL_DH_RESERVED = 6,
    S2N_CERT_TYPE_FORTEZZA_DMS_RESERVED = 20,
    S2N_CERT_TYPE_ECDSA_SIGN = 64,
    S2N_CERT_TYPE_RSA_FIXED_ECDH = 65,
    S2N_CERT_TYPE_ECDSA_FIXED_ECDH = 66,
} s2n_cert_type;

struct s2n_pkey;
typedef struct s2n_pkey s2n_cert_public_key;
typedef struct s2n_pkey s2n_cert_private_key;

extern int s2n_cert_public_key_set_rsa_from_openssl(s2n_cert_public_key *cert_pub_key, RSA *openssl_rsa);

extern uint64_t s2n_connection_get_wire_bytes_in(struct s2n_connection *conn);
extern uint64_t s2n_connection_get_wire_bytes_out(struct s2n_connection *conn);
extern int s2n_connection_get_client_protocol_version(struct s2n_connection *conn);
extern int s2n_connection_get_server_protocol_version(struct s2n_connection *conn);
extern int s2n_connection_get_actual_protocol_version(struct s2n_connection *conn);
extern int s2n_connection_get_client_hello_version(struct s2n_connection *conn);
extern int s2n_connection_client_cert_used(struct s2n_connection *conn);
extern const char *s2n_connection_get_cipher(struct s2n_connection *conn);
extern int s2n_connection_is_valid_for_cipher_preferences(struct s2n_connection *conn, const char *version);
extern const char *s2n_connection_get_curve(struct s2n_connection *conn);
extern const char *s2n_connection_get_kem_name(struct s2n_connection *conn);
extern int s2n_connection_get_alert(struct s2n_connection *conn);
extern const char *s2n_connection_get_handshake_type_name(struct s2n_connection *conn);
extern const char *s2n_connection_get_last_message_name(struct s2n_connection *conn);

#ifdef __cplusplus
}
#endif
