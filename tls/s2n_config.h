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

#include "api/s2n.h"
#include "crypto/s2n_certificate.h"
#include "crypto/s2n_dhe.h"
#include "tls/s2n_resume.h"
#include "tls/s2n_x509_validator.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_set.h"
#include "tls/s2n_psk.h"

#define S2N_MAX_TICKET_KEYS 48
#define S2N_MAX_TICKET_KEY_HASHES 500 /* 10KB */

struct s2n_cipher_preferences;

struct s2n_config {
    /* The following bitfield flags are used in SAW proofs. The positions of
     * these flags are important, as SAW looks up each flag by their index
     * in the struct starting from 0. See the comments surrounding
     * config_bitfield in tests/saw/spec/handshake/handshake_io_lowlevel.saw for
     * more details. Make sure that any new flags are added after these ones
     * so that the indices in the SAW proofs do not need to be changed each time.
     *
     * START OF SAW-TRACKED BITFIELD FLAGS */

    unsigned use_tickets:1;

    /* Whether a connection can be used by a QUIC implementation.
     * See s2n_quic_support.h */
    unsigned quic_enabled:1;

    /* END OF SAW-TRACKED BITFIELD FLAGS */

    unsigned cert_allocated:1;
    unsigned default_certs_are_explicit:1;
    unsigned use_session_cache:1;
    /* if this is FALSE, server will ignore client's Maximum Fragment Length request */
    unsigned accept_mfl:1;
    unsigned check_ocsp:1;
    unsigned disable_x509_validation:1;
    unsigned max_verify_cert_chain_depth_set:1;
    /* Whether to add dss cert type during a server certificate request.
     * See https://github.com/aws/s2n-tls/blob/main/docs/USAGE-GUIDE.md */
    unsigned cert_req_dss_legacy_compat_enabled:1;
    /* Whether any RSA certificates have been configured server-side to send to clients. This is needed so that the
     * server knows whether or not to self-downgrade to TLS 1.2 if the server is compiled with Openssl 1.0.2 and does
     * not support RSA PSS signing (which is required for TLS 1.3). */
    unsigned is_rsa_cert_configured:1;
    /* It's possible to use a certificate without loading the private key,
     * but async signing must be enabled. Use this flag to enforce that restriction.
     */
    unsigned no_signing_key:1;

    struct s2n_dh_params *dhparams;
    /* Needed until we can deprecate s2n_config_add_cert_chain_and_key. This is
     * used to release memory allocated only in the deprecated API that the application 
     * does not have a reference to. */
    struct s2n_map *domain_name_to_cert_map;
    struct certs_by_type default_certs_by_type;
    struct s2n_blob application_protocols;
    s2n_status_request_type status_request_type;
    s2n_clock_time_nanoseconds wall_clock;
    s2n_clock_time_nanoseconds monotonic_clock;

    const struct s2n_security_policy *security_policy;

    void *sys_clock_ctx;
    void *monotonic_clock_ctx;

    s2n_client_hello_fn *client_hello_cb;
    s2n_client_hello_cb_mode client_hello_cb_mode;

    void *client_hello_cb_ctx;

    uint64_t session_state_lifetime_in_nanos;

    struct s2n_set *ticket_keys;
    struct s2n_set *ticket_key_hashes;
    uint64_t encrypt_decrypt_key_lifetime_in_nanos;
    uint64_t decrypt_key_lifetime_in_nanos;

    /* If session cache is being used, these must all be set */
    s2n_cache_store_callback cache_store;
    void *cache_store_data;

    s2n_cache_retrieve_callback cache_retrieve;
    void *cache_retrieve_data;

    s2n_cache_delete_callback cache_delete;
    void *cache_delete_data;

    s2n_ct_support_level ct_type;

    s2n_cert_auth_type client_cert_auth_type;

    s2n_alert_behavior alert_behavior;

    /* Return TRUE if the host should be trusted, If FALSE this will likely be called again for every host/alternative name
     * in the certificate. If any respond TRUE. If none return TRUE, the cert will be considered untrusted. */
    uint8_t (*verify_host)(const char *host_name, size_t host_name_len, void *data);
    void *data_for_verify_host;

    /* Application supplied callback to resolve domain name conflicts when loading certs. */
    s2n_cert_tiebreak_callback cert_tiebreak_cb;

    uint8_t mfl_code;

    uint8_t initial_tickets_to_send;

    struct s2n_x509_trust_store trust_store;
    uint16_t max_verify_cert_chain_depth;

    s2n_async_pkey_fn async_pkey_cb;

    s2n_psk_selection_callback psk_selection_cb;
    void *psk_selection_ctx;

    s2n_key_log_fn key_log_cb;
    void *key_log_ctx;

    s2n_session_ticket_fn session_ticket_cb;
    void *session_ticket_ctx;

    s2n_early_data_cb early_data_cb;

    uint32_t server_max_early_data_size;

    s2n_psk_mode psk_mode;

    s2n_async_pkey_validation_mode async_pkey_validation_mode;
};

S2N_CLEANUP_RESULT s2n_config_ptr_free(struct s2n_config **config);

int s2n_config_defaults_init(void);
extern struct s2n_config *s2n_fetch_default_config(void);
int s2n_config_set_unsafe_for_testing(struct s2n_config *config);

int s2n_config_init_session_ticket_keys(struct s2n_config *config);
int s2n_config_free_session_ticket_keys(struct s2n_config *config);

void s2n_wipe_static_configs(void);
extern struct s2n_cert_chain_and_key *s2n_config_get_single_default_cert(struct s2n_config *config);
int s2n_config_get_num_default_certs(struct s2n_config *config);
