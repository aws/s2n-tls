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

#define S2N_SSLv2 20
#define S2N_SSLv3 30
#define S2N_TLS10 31
#define S2N_TLS11 32
#define S2N_TLS12 33

extern __thread int s2n_errno;

typedef enum {
    S2N_ERR_OK,
    S2N_ERR_IO,
    S2N_ERR_BLOCKED,
    S2N_ERR_KEY_INIT,
    S2N_ERR_ENCRYPT,
    S2N_ERR_DECRYPT,
    S2N_ERR_MADVISE,
    S2N_ERR_ALLOC,
    S2N_ERR_MLOCK,
    S2N_ERR_MUNLOCK,
    S2N_ERR_FSTAT,
    S2N_ERR_OPEN,
    S2N_ERR_MMAP,
    S2N_ERR_NULL,
    S2N_ERR_CLOSED,
    S2N_ERR_SAFETY,
    S2N_ERR_NOT_INITIALIZED,
    S2N_ERR_RANDOM_UNITIALIZED,
    S2N_ERR_OPEN_RANDOM,
    S2N_ERR_RESIZE_STATIC_STUFFER,
    S2N_ERR_RESIZE_TAINTED_STUFFER,
    S2N_ERR_STUFFER_OUT_OF_DATA,
    S2N_ERR_STUFFER_IS_FULL,
    S2N_ERR_INVALID_BASE64,
    S2N_ERR_INVALID_PEM,
    S2N_ERR_DH_COPYING_PARAMETERS,
    S2N_ERR_DH_COPYING_PUBLIC_KEY,
    S2N_ERR_DH_GENERATING_PARAMETERS,
    S2N_ERR_DH_PARAMS_CREATE,
    S2N_ERR_DH_SERIAZING,
    S2N_ERR_DH_SHARED_SECRET,
    S2N_ERR_DH_WRITING_PUBLIC_KEY,
    S2N_ERR_DH_FAILED_SIGNING,
    S2N_ERR_DH_TOO_SMALL,
    S2N_ERR_DH_PARAMETER_CHECK,
    S2N_ERR_INVALID_PKCS3,
    S2N_ERR_HASH_DIGEST_FAILED,
    S2N_ERR_HASH_INIT_FAILED,
    S2N_ERR_HASH_INVALID_ALGORITHM,
    S2N_ERR_HASH_UPDATE_FAILED,
    S2N_ERR_HMAC_INVALID_ALGORITHM,
    S2N_ERR_PRF_INVALID_ALGORITHM,
    S2N_ERR_SIZE_MISMATCH,
    S2N_ERR_DECODE_CERTIFICATE,
    S2N_ERR_DECODE_PRIVATE_KEY,
    S2N_ERR_KEY_MISMATCH,
    S2N_ERR_NOMEM,
    S2N_ERR_SIGN,
    S2N_ERR_VERIFY_SIGNATURE,
    S2N_ERR_ALERT_PRESENT,
    S2N_ERR_ALERT,
    S2N_ERR_CBC_VERIFY,
    S2N_ERR_CIPHER_NOT_SUPPORTED,
    S2N_ERR_BAD_MESSAGE,
    S2N_ERR_INVALID_SIGNATURE_ALGORITHM,
    S2N_ERR_NO_CERTIFICATE_IN_PEM,
    S2N_ERR_NO_ALERT,
    S2N_ERR_CLIENT_MODE,
    S2N_ERR_SERVER_NAME_TOO_LONG,
    S2N_ERR_CLIENT_MODE_DISABLED,
    S2N_ERR_HANDSHAKE_STATE,
    S2N_ERR_FALLBACK_DETECTED,
    S2N_ERR_INVALID_CIPHER_PREFERENCES,
    S2N_ERR_APPLICATION_PROTOCOL_TOO_LONG,
    S2N_ERR_NO_APPLICATION_PROTOCOL,
    S2N_ERR_DRBG,
    S2N_ERR_DRBG_REQUEST_SIZE,
    S2N_ERR_ECDHE_GEN_KEY,
    S2N_ERR_ECDHE_SHARED_SECRET,
    S2N_ERR_ECDHE_UNSUPPORTED_CURVE,
    S2N_ERR_ECDHE_SERIALIZING,
    S2N_ERR_SHUTDOWN_PAUSED,
} s2n_error;


struct s2n_config;

extern int s2n_init(void);
extern int s2n_cleanup(void);
extern struct s2n_config *s2n_config_new(void);
extern int s2n_config_free(struct s2n_config *config);
extern int s2n_config_free_dhparams(struct s2n_config *config);
extern int s2n_config_free_cert_chain_and_key(struct s2n_config *config);
extern int s2n_config_set_nanoseconds_since_epoch_callback(struct s2n_config *config, int (*nanoseconds_since_epoch)(void *, uint64_t *), void * data);
extern const char *s2n_strerror(int error, const char *lang);

extern int s2n_config_add_cert_chain_and_key(struct s2n_config *config, char *cert_chain_pem, char *private_key_pem);
extern int s2n_config_add_cert_chain_and_key_with_status(struct s2n_config *config,
        char *cert_chain_pem, char *private_key_pem, const uint8_t *status, uint32_t length);
extern int s2n_config_add_dhparams(struct s2n_config *config, char *dhparams_pem);
extern int s2n_config_set_cipher_preferences(struct s2n_config *config, const char *version);
extern int s2n_config_set_protocol_preferences(struct s2n_config *config, const char * const *protocols, int protocol_count);
typedef enum { S2N_STATUS_REQUEST_NONE = 0, S2N_STATUS_REQUEST_OCSP = 1 } s2n_status_request_type;
extern int s2n_config_set_status_request_type(struct s2n_config *config, s2n_status_request_type type);

struct s2n_connection;
typedef enum { S2N_SERVER, S2N_CLIENT } s2n_mode;
extern struct s2n_connection *s2n_connection_new(s2n_mode mode);
extern int s2n_connection_set_config(struct s2n_connection *conn, struct s2n_config *config);

extern int s2n_connection_set_fd(struct s2n_connection *conn, int readfd);
extern int s2n_connection_set_read_fd(struct s2n_connection *conn, int readfd);
extern int s2n_connection_set_write_fd(struct s2n_connection *conn, int readfd);

extern int s2n_connection_prefer_throughput(struct s2n_connection *conn);
extern int s2n_connection_prefer_low_latency(struct s2n_connection *conn);

typedef enum { S2N_BUILT_IN_BLINDING, S2N_SELF_SERVICE_BLINDING } s2n_blinding;
extern int s2n_connection_set_blinding(struct s2n_connection *conn, s2n_blinding blinding);
extern int64_t s2n_connection_get_delay(struct s2n_connection *conn);

extern int s2n_set_server_name(struct s2n_connection *conn, const char *server_name);
extern const char *s2n_get_server_name(struct s2n_connection *conn);
extern const char *s2n_get_application_protocol(struct s2n_connection *conn);
extern const uint8_t *s2n_connection_get_ocsp_response(struct s2n_connection *conn, uint32_t *length);

typedef enum { S2N_NOT_BLOCKED = 0, S2N_BLOCKED_ON_READ, S2N_BLOCKED_ON_WRITE } s2n_blocked_status;
extern int s2n_negotiate(struct s2n_connection *conn, s2n_blocked_status *blocked);
extern ssize_t s2n_send(struct s2n_connection *conn, void *buf, ssize_t size, s2n_blocked_status *blocked);
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
extern int s2n_connection_get_alert(struct s2n_connection *conn);

#ifdef __cplusplus
}
#endif
