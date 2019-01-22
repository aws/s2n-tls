/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_dhe.h"

#include "utils/s2n_blob.h"
#include "api/s2n.h"

#include "tls/s2n_x509_validator.h"
#include "tls/s2n_resume.h"

#define S2N_MAX_SERVER_NAME 256
#define S2N_MAX_TICKET_KEYS 48
#define S2N_MAX_TICKET_KEY_HASHES 500 /* 10KB */

struct s2n_cipher_preferences;

/* struct used to carry back the decrypt output for RSA handshake or signed hash signature for DHE/ECDHE handshake */
struct s2n_external_ctx {
  /* Flag to indicate status of external request (decrypt for RSA or sign for DHE/ECDHE). The possible status are:
   *   0 - external request has not been invoked yet;
   *   1 - external request has been invoked but not result has come back yet;
   *   2 - external request has completed and output is copied to the byte array result.
   *   3 - external request has completed but error occurred.
   */
  uint8_t status;

  /* The 1st to the 4th byte (Big Endian) is a uint32_t which is the size of the byte array that contains the output or
   * signature. From the 5th byte till the end will be the actual output or signature.
   */
  uint8_t *result;

  /* Temporary io used ot carry ephemeral from SERVER_KEY_EXTERNAL to SERVER_KEY so that we don't need to write data to
   * the handshake io in SERVER_KEY_EXTERNAL which will cause handshake error in the receive functions due to incomplete data.
   */
  struct s2n_stuffer ephemeral_key_io;
};

struct s2n_config {
    struct s2n_dh_params *dhparams;
    struct s2n_cert_chain_and_key *cert_and_key_pairs;
    const struct s2n_cipher_preferences *cipher_preferences;
    struct s2n_blob application_protocols;
    s2n_status_request_type status_request_type;
    s2n_clock_time_nanoseconds wall_clock;
    s2n_clock_time_nanoseconds monotonic_clock;

    void *sys_clock_ctx;
    void *monotonic_clock_ctx;

    s2n_client_hello_fn *client_hello_cb;
    void *client_hello_cb_ctx;

    uint64_t session_state_lifetime_in_nanos;

    uint8_t use_tickets;
    struct s2n_array *ticket_keys;
    struct s2n_array *ticket_key_hashes;
    uint64_t encrypt_decrypt_key_lifetime_in_nanos;
    uint64_t decrypt_key_lifetime_in_nanos;

    /* If caching is being used, these must all be set */
    int (*cache_store) (void *data, uint64_t ttl_in_seconds, const void *key, uint64_t key_size, const void *value, uint64_t value_size);
    void *cache_store_data;

    int (*cache_retrieve) (void *data, const void *key, uint64_t key_size, void *value, uint64_t * value_size);
    void *cache_retrieve_data;

    int (*cache_delete) (void *data, const void *key, uint64_t key_size);
    void *cache_delete_data;

    s2n_ct_support_level ct_type;

    s2n_cert_auth_type client_cert_auth_type;

    s2n_alert_behavior alert_behavior;

    /* Return TRUE if the host should be trusted, If FALSE this will likely be called again for every host/alternative name
     * in the certificate. If any respond TRUE. If none return TRUE, the cert will be considered untrusted. */
    uint8_t (*verify_host) (const char *host_name, size_t host_name_len, void *data);
    void *data_for_verify_host;

    uint8_t mfl_code;

    /* if this is FALSE, server will ignore client's Maximum Fragment Length request */
    int accept_mfl;

    struct s2n_x509_trust_store trust_store;
    uint8_t check_ocsp;
    uint8_t disable_x509_validation;
    uint16_t max_verify_cert_chain_depth;
    uint8_t max_verify_cert_chain_depth_set;

    rsa_decrypt_async_fn external_rsa_decrypt;
    dhe_sign_async_fn external_dhe_sign;

    /* Byte array used to carry back the decrypt result for RSA handshake
     *   The first byte will be used as flag to indicate status, the status are:
     *      1:  external rsa decrypt has been called but not result has come back yet;
     *      2:  external rsa decrypt has completed the request and the decrypted pre-master secret is copied to to this
     *          byte array.
     *      3:  external rsa decrypt has completed the request but error occurred.
     *   The 2nd to the 5th byte (Big Endian) will be a uint32_t which is the size of decrypted pre-master secret.
     *   From the 6th byte till the end will be the decrypted pre-master secret.
     *   The total length of this byte array is 54 = 1 + 5 + S2N_TLS_SECRET_LEN (48)*/
    void *external_rsa_ctx;

    struct s2n_external_ctx external_dhe_ctx;
};

extern struct s2n_config *s2n_fetch_default_config(void);
extern struct s2n_config *s2n_fetch_default_fips_config(void);
extern struct s2n_config *s2n_fetch_unsafe_client_testing_config(void);
extern struct s2n_config *s2n_fetch_unsafe_client_ecdsa_testing_config(void);

extern int s2n_config_init_session_ticket_keys(struct s2n_config *config);
extern int s2n_config_free_session_ticket_keys(struct s2n_config *config);

extern void s2n_wipe_static_configs(void);
extern int s2n_config_add_cert_chain_from_stuffer(struct s2n_config *config, struct s2n_stuffer *chain_in_stuffer);
extern int s2n_config_add_cert_chain(struct s2n_config *config, const char *cert_chain_pem);
extern int s2n_config_add_private_key(struct s2n_config *config, const char *private_key_pem);
int s2n_config_get_cert_type(struct s2n_config *config, s2n_cert_type *cert_type);
