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

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_dhe.h"

#include "utils/s2n_blob.h"
#include "api/s2n.h"

#include "tls/s2n_x509_validator.h"
#include "tls/s2n_resume.h"

#define S2N_MAX_TICKET_KEYS 48
#define S2N_MAX_TICKET_KEY_HASHES 500 /* 10KB */

struct s2n_cipher_preferences;

struct s2n_config {
    struct s2n_dh_params *dhparams;
    /* Needed until we can deprecate s2n_config_add_cert_chain_and_key. This is
     * used to release memory allocated only in the deprecated API that the application 
     * does not have a reference to. */
    unsigned cert_allocated:1;
    struct s2n_map *domain_name_to_cert_map;
    unsigned default_certs_are_explicit:1;
    struct auth_method_to_cert_value default_cert_per_auth_method;
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
    uint8_t (*verify_host) (const char *host_name, size_t host_name_len, void *data);
    void *data_for_verify_host;

    /* Application supplied callback to resolve domain name conflicts when loading certs. */
    s2n_cert_tiebreak_callback cert_tiebreak_cb;

    uint8_t mfl_code;

    /* if this is FALSE, server will ignore client's Maximum Fragment Length request */
    int accept_mfl;

    struct s2n_x509_trust_store trust_store;
    uint8_t check_ocsp;
    uint8_t disable_x509_validation;
    uint16_t max_verify_cert_chain_depth;
    uint8_t max_verify_cert_chain_depth_set;
};

extern struct s2n_config *s2n_fetch_default_config(void);
extern struct s2n_config *s2n_fetch_default_fips_config(void);
extern struct s2n_config *s2n_fetch_unsafe_client_testing_config(void);
extern struct s2n_config *s2n_fetch_unsafe_client_ecdsa_testing_config(void);

extern int s2n_config_init_session_ticket_keys(struct s2n_config *config);
extern int s2n_config_free_session_ticket_keys(struct s2n_config *config);

extern void s2n_wipe_static_configs(void);
int s2n_config_get_cert_type(struct s2n_config *config, s2n_cert_type *cert_type);
extern struct s2n_cert_chain_and_key *s2n_config_get_single_default_cert(struct s2n_config *config);
extern int s2n_config_get_num_default_certs(struct s2n_config *config);
