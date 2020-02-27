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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>

/* Function return code  */
#define S2N_SUCCESS 0
#define S2N_FAILURE -1

/* Callback return code */
#define S2N_CALLBACK_BLOCKED -2

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

/*
 * To easily retrieve error types, we split error values into two parts.
 * The upper 6 bits describe the error type and the lower bits describe the value within the category.
 * [ Error Type Bits(31-26) ][ Value Bits(25-0) ]
 */
#define S2N_ERR_NUM_VALUE_BITS 26

/* Start value for each error type. */
#define S2N_ERR_T_OK_START (S2N_ERR_T_OK << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_IO_START (S2N_ERR_T_IO << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_CLOSED_START (S2N_ERR_T_CLOSED << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_BLOCKED_START (S2N_ERR_T_BLOCKED << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_ALERT_START (S2N_ERR_T_ALERT << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_PROTO_START (S2N_ERR_T_PROTO << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_INTERNAL_START (S2N_ERR_T_INTERNAL << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_USAGE_START (S2N_ERR_T_USAGE << S2N_ERR_NUM_VALUE_BITS)

/* Order of values in this enum is important. New error values should be placed at the end of their respective category.
 * For example, a new TLS protocol related error belongs in the S2N_ERR_T_PROTO category. It should be placed
 * immediately before S2N_ERR_T_INTERNAL_START(the first value of he next category).
 */
typedef enum {
    /* S2N_ERR_T_OK */
    S2N_ERR_OK = S2N_ERR_T_OK_START,
    S2N_ERR_T_OK_END,

    /* S2N_ERR_T_IO */
    S2N_ERR_IO = S2N_ERR_T_IO_START,
    S2N_ERR_T_IO_END,

    /* S2N_ERR_T_CLOSED */
    S2N_ERR_CLOSED = S2N_ERR_T_CLOSED_START,
    S2N_ERR_T_CLOSED_END,

    /* S2N_ERR_T_BLOCKED */
    S2N_ERR_BLOCKED = S2N_ERR_T_BLOCKED_START,
    S2N_ERR_T_BLOCKED_END,

    /* S2N_ERR_T_ALERT */
    S2N_ERR_ALERT = S2N_ERR_T_ALERT_START,
    S2N_ERR_T_ALERT_END,

    /* S2N_ERR_T_PROTO */
    S2N_ERR_ENCRYPT = S2N_ERR_T_PROTO_START,
    S2N_ERR_DECRYPT,
    S2N_ERR_BAD_MESSAGE,
    S2N_ERR_KEY_INIT,
    S2N_ERR_DH_SERIALIZING,
    S2N_ERR_DH_SHARED_SECRET,
    S2N_ERR_DH_WRITING_PUBLIC_KEY,
    S2N_ERR_DH_FAILED_SIGNING,
    S2N_ERR_DH_COPYING_PARAMETERS,
    S2N_ERR_DH_GENERATING_PARAMETERS,
    S2N_ERR_CIPHER_NOT_SUPPORTED,
    S2N_ERR_NO_APPLICATION_PROTOCOL,
    S2N_ERR_FALLBACK_DETECTED,
    S2N_ERR_HASH_DIGEST_FAILED,
    S2N_ERR_HASH_INIT_FAILED,
    S2N_ERR_HASH_UPDATE_FAILED,
    S2N_ERR_HASH_COPY_FAILED,
    S2N_ERR_HASH_WIPE_FAILED,
    S2N_ERR_HASH_NOT_READY,
    S2N_ERR_ALLOW_MD5_FOR_FIPS_FAILED,
    S2N_ERR_DECODE_CERTIFICATE,
    S2N_ERR_DECODE_PRIVATE_KEY,
    S2N_ERR_INVALID_SIGNATURE_ALGORITHM,
    S2N_ERR_INVALID_SIGNATURE_SCHEME,
    S2N_ERR_EMPTY_SIGNATURE_SCHEME,
    S2N_ERR_CBC_VERIFY,
    S2N_ERR_DH_COPYING_PUBLIC_KEY,
    S2N_ERR_SIGN,
    S2N_ERR_VERIFY_SIGNATURE,
    S2N_ERR_ECDHE_GEN_KEY,
    S2N_ERR_ECDHE_SHARED_SECRET,
    S2N_ERR_ECDHE_UNSUPPORTED_CURVE,
    S2N_ERR_ECDSA_UNSUPPORTED_CURVE,
    S2N_ERR_ECDHE_SERIALIZING,
    S2N_ERR_KEM_UNSUPPORTED_PARAMS,
    S2N_ERR_SHUTDOWN_RECORD_TYPE,
    S2N_ERR_SHUTDOWN_CLOSED,
    S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO,
    S2N_ERR_RECORD_LIMIT,
    S2N_ERR_CERT_UNTRUSTED,
    S2N_ERR_CERT_TYPE_UNSUPPORTED,
    S2N_ERR_INVALID_MAX_FRAG_LEN,
    S2N_ERR_MAX_FRAG_LEN_MISMATCH,
    S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED,
    S2N_ERR_BAD_KEY_SHARE,
    S2N_ERR_CANCELLED,
    S2N_ERR_PROTOCOL_DOWNGRADE_DETECTED,
    S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS,
    S2N_ERR_T_PROTO_END,

    /* S2N_ERR_T_INTERNAL */
    S2N_ERR_MADVISE = S2N_ERR_T_INTERNAL_START,
    S2N_ERR_ALLOC,
    S2N_ERR_MLOCK,
    S2N_ERR_MUNLOCK,
    S2N_ERR_FSTAT,
    S2N_ERR_OPEN,
    S2N_ERR_MMAP,
    S2N_ERR_ATEXIT,
    S2N_ERR_NOMEM,
    S2N_ERR_NULL,
    S2N_ERR_SAFETY,
    S2N_ERR_NOT_INITIALIZED,
    S2N_ERR_RANDOM_UNINITIALIZED,
    S2N_ERR_OPEN_RANDOM,
    S2N_ERR_RESIZE_STATIC_STUFFER,
    S2N_ERR_RESIZE_TAINTED_STUFFER,
    S2N_ERR_STUFFER_OUT_OF_DATA,
    S2N_ERR_STUFFER_IS_FULL,
    S2N_ERR_STUFFER_NOT_FOUND,
    S2N_ERR_STUFFER_HAS_UNPROCESSED_DATA,
    S2N_ERR_HASH_INVALID_ALGORITHM,
    S2N_ERR_PRF_INVALID_ALGORITHM,
    S2N_ERR_PRF_INVALID_SEED,
    S2N_ERR_P_HASH_INVALID_ALGORITHM,
    S2N_ERR_P_HASH_INIT_FAILED,
    S2N_ERR_P_HASH_UPDATE_FAILED,
    S2N_ERR_P_HASH_FINAL_FAILED,
    S2N_ERR_P_HASH_WIPE_FAILED,
    S2N_ERR_HMAC_INVALID_ALGORITHM,
    S2N_ERR_HKDF_OUTPUT_SIZE,
    S2N_ERR_ALERT_PRESENT,
    S2N_ERR_HANDSHAKE_STATE,
    S2N_ERR_SHUTDOWN_PAUSED,
    S2N_ERR_SIZE_MISMATCH,
    S2N_ERR_DRBG,
    S2N_ERR_DRBG_REQUEST_SIZE,
    S2N_ERR_KEY_CHECK,
    S2N_ERR_CIPHER_TYPE,
    S2N_ERR_MAP_DUPLICATE,
    S2N_ERR_MAP_IMMUTABLE,
    S2N_ERR_MAP_MUTABLE,
    S2N_ERR_MAP_INVALID_MAP_SIZE,
    S2N_ERR_INITIAL_HMAC,
    S2N_ERR_INVALID_NONCE_TYPE,
    S2N_ERR_UNIMPLEMENTED,
    S2N_ERR_READ,
    S2N_ERR_WRITE,
    S2N_ERR_BAD_FD,
    S2N_ERR_RDRAND_FAILED,
    S2N_ERR_FAILED_CACHE_RETRIEVAL,
    S2N_ERR_X509_TRUST_STORE,
    S2N_ERR_UNKNOWN_PROTOCOL_VERSION,
    S2N_ERR_NULL_CN_NAME,
    S2N_ERR_NULL_SANS,
    S2N_ERR_CLIENT_HELLO_VERSION,
    S2N_ERR_CLIENT_PROTOCOL_VERSION,
    S2N_ERR_SERVER_PROTOCOL_VERSION,
    S2N_ERR_ACTUAL_PROTOCOL_VERSION,
    S2N_ERR_POLLING_FROM_SOCKET,
    S2N_ERR_RECV_STUFFER_FROM_CONN,
    S2N_ERR_SEND_STUFFER_TO_CONN,
    S2N_ERR_PRECONDITION_VIOLATION,
    S2N_ERR_INTEGER_OVERFLOW,
    S2N_ERR_ARRAY_INDEX_OOB,
    S2N_ERR_FREE_STATIC_BLOB,
    S2N_ERR_RESIZE_STATIC_BLOB,
    S2N_ERR_T_INTERNAL_END,

    /* S2N_ERR_T_USAGE */
    S2N_ERR_NO_ALERT = S2N_ERR_T_USAGE_START,
    S2N_ERR_CLIENT_MODE,
    S2N_ERR_CLIENT_MODE_DISABLED,
    S2N_ERR_TOO_MANY_CERTIFICATES,
    S2N_ERR_TOO_MANY_SIGNATURE_SCHEMES,
    S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_FIPS_MODE,
    S2N_ERR_INVALID_BASE64,
    S2N_ERR_INVALID_HEX,
    S2N_ERR_INVALID_PEM,
    S2N_ERR_DH_PARAMS_CREATE,
    S2N_ERR_DH_TOO_SMALL,
    S2N_ERR_DH_PARAMETER_CHECK,
    S2N_ERR_INVALID_PKCS3,
    S2N_ERR_NO_CERTIFICATE_IN_PEM,
    S2N_ERR_SERVER_NAME_TOO_LONG,
    S2N_ERR_NUM_DEFAULT_CERTIFICATES,
    S2N_ERR_MULTIPLE_DEFAULT_CERTIFICATES_PER_AUTH_TYPE,
    S2N_ERR_INVALID_CIPHER_PREFERENCES,
    S2N_ERR_APPLICATION_PROTOCOL_TOO_LONG,
    S2N_ERR_KEY_MISMATCH,
    S2N_ERR_SEND_SIZE,
    S2N_ERR_CORK_SET_ON_UNMANAGED,
    S2N_ERR_UNRECOGNIZED_EXTENSION,
    S2N_ERR_INVALID_SCT_LIST,
    S2N_ERR_INVALID_OCSP_RESPONSE,
    S2N_ERR_UPDATING_EXTENSION,
    S2N_ERR_INVALID_SERIALIZED_SESSION_STATE,
    S2N_ERR_SERIALIZED_SESSION_STATE_TOO_LONG,
    S2N_ERR_SESSION_ID_TOO_LONG,
    S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_SESSION_RESUMPTION_MODE,
    S2N_ERR_INVALID_TICKET_KEY_LENGTH,
    S2N_ERR_INVALID_TICKET_KEY_NAME_OR_NAME_LENGTH,
    S2N_ERR_TICKET_KEY_NOT_UNIQUE,
    S2N_ERR_TICKET_KEY_LIMIT,
    S2N_ERR_NO_TICKET_ENCRYPT_DECRYPT_KEY,
    S2N_ERR_ENCRYPT_DECRYPT_KEY_SELECTION_FAILED,
    S2N_ERR_KEY_USED_IN_SESSION_TICKET_NOT_FOUND,
    S2N_ERR_SENDING_NST,
    S2N_ERR_INVALID_DYNAMIC_THRESHOLD,
    S2N_ERR_INVALID_ARGUMENT,
    S2N_ERR_NOT_IN_UNIT_TEST,
    S2N_ERR_UNSUPPORTED_CPU,
    S2N_ERR_SESSION_ID_TOO_SHORT,
    S2N_ERR_CONNECTION_CACHING_DISALLOWED,
    S2N_ERR_SESSION_TICKET_NOT_SUPPORTED,
    S2N_ERR_OCSP_NOT_SUPPORTED,
    S2N_ERR_INVALID_SIGNATURE_ALGORITHMS_PREFERENCES,
    S2N_ERR_T_USAGE_END,
} s2n_error;

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
extern int s2n_config_set_signature_preferences(struct s2n_config *config, const char *version);
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
extern int s2n_config_set_session_cache_onoff(struct s2n_config *config, uint8_t enabled);
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

struct s2n_pkey;
typedef struct s2n_pkey s2n_cert_public_key;
typedef struct s2n_pkey s2n_cert_private_key;

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
