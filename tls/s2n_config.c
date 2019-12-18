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

#include <strings.h>
#include <time.h>

#include "error/s2n_errno.h"

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_fips.h"

#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"
#include "crypto/s2n_hkdf.h"
#include "utils/s2n_map.h"
#include "utils/s2n_blob.h"

#if defined(CLOCK_MONOTONIC_RAW)
#define S2N_CLOCK_HW CLOCK_MONOTONIC_RAW
#else
#define S2N_CLOCK_HW CLOCK_MONOTONIC
#endif

#define S2N_CLOCK_SYS CLOCK_REALTIME

static int monotonic_clock(void *data, uint64_t *nanoseconds)
{
    struct timespec current_time = {0};

    GUARD(clock_gettime(S2N_CLOCK_HW, &current_time));

    *nanoseconds = (uint64_t)current_time.tv_sec * 1000000000ull;
    *nanoseconds += current_time.tv_nsec;

    return 0;
}

static int wall_clock(void *data, uint64_t *nanoseconds)
{
    struct timespec current_time = {0};

    GUARD(clock_gettime(S2N_CLOCK_SYS, &current_time));

    *nanoseconds = (uint64_t)current_time.tv_sec * 1000000000ull;
    *nanoseconds += current_time.tv_nsec;

    return 0;
}

static uint8_t default_config_init = 0;
static uint8_t unsafe_client_testing_config_init = 0;
static uint8_t unsafe_client_ecdsa_testing_config_init = 0;
static uint8_t default_client_config_init = 0;
static uint8_t default_fips_config_init = 0;

static struct s2n_config s2n_default_config = {0};

/* This config should only used by the s2n_client for unit/integration testing purposes. */
static struct s2n_config s2n_unsafe_client_testing_config = {0};

static struct s2n_config s2n_unsafe_client_ecdsa_testing_config = {0};

static struct s2n_config default_client_config = {0};

static struct s2n_config s2n_default_fips_config = {0};

static int s2n_config_init(struct s2n_config *config)
{
    config->cert_allocated = 0;
    config->dhparams = NULL;
    memset(&config->application_protocols, 0, sizeof(config->application_protocols));
    config->status_request_type = S2N_STATUS_REQUEST_NONE;
    config->wall_clock = wall_clock;
    config->monotonic_clock = monotonic_clock;
    config->verify_host = NULL;
    config->data_for_verify_host = NULL;
    config->client_hello_cb = NULL;
    config->client_hello_cb_ctx = NULL;
    config->cache_store = NULL;
    config->cache_store_data = NULL;
    config->cache_retrieve = NULL;
    config->cache_retrieve_data = NULL;
    config->cache_delete = NULL;
    config->cache_delete_data = NULL;
    config->ct_type = S2N_CT_SUPPORT_NONE;
    config->mfl_code = S2N_TLS_MAX_FRAG_LEN_EXT_NONE;
    config->alert_behavior = S2N_ALERT_FAIL_ON_WARNINGS;
    config->accept_mfl = 0;
    config->session_state_lifetime_in_nanos = S2N_STATE_LIFETIME_IN_NANOS;
    config->use_tickets = 0;
    config->ticket_keys = NULL;
    config->ticket_key_hashes = NULL;
    config->encrypt_decrypt_key_lifetime_in_nanos = S2N_TICKET_ENCRYPT_DECRYPT_KEY_LIFETIME_IN_NANOS;
    config->decrypt_key_lifetime_in_nanos = S2N_TICKET_DECRYPT_KEY_LIFETIME_IN_NANOS;

    /* By default, only the client will authenticate the Server's Certificate. The Server does not request or
     * authenticate any client certificates. */
    config->client_cert_auth_type = S2N_CERT_AUTH_NONE;
    config->check_ocsp = 1;
    config->disable_x509_validation = 0;
    config->max_verify_cert_chain_depth = 0;
    config->max_verify_cert_chain_depth_set = 0;

    config->cert_tiebreak_cb = NULL;

    s2n_config_set_cipher_preferences(config, "default");

    if (s2n_is_in_fips_mode()) {
        s2n_config_set_cipher_preferences(config, "default_fips");
    }

    if (s2n_is_tls13_enabled()) {
        s2n_config_set_cipher_preferences(config, "default_tls13");
    }

    notnull_check(config->domain_name_to_cert_map = s2n_map_new_with_initial_capacity(1));
    GUARD(s2n_map_complete(config->domain_name_to_cert_map));
    memset(&config->default_cert_per_auth_method, 0, sizeof(struct auth_method_to_cert_value));
    config->default_certs_are_explicit = 0;

    s2n_x509_trust_store_init_empty(&config->trust_store);
    s2n_x509_trust_store_from_system_defaults(&config->trust_store);

    return 0;
}

static int s2n_config_cleanup(struct s2n_config *config)
{
    s2n_x509_trust_store_wipe(&config->trust_store);
    config->check_ocsp = 0;

    GUARD(s2n_config_free_session_ticket_keys(config));
    GUARD(s2n_config_free_cert_chain_and_key(config));
    GUARD(s2n_config_free_dhparams(config));
    GUARD(s2n_free(&config->application_protocols));
    GUARD(s2n_map_free(config->domain_name_to_cert_map));

    return 0;
}

static int s2n_config_update_domain_name_to_cert_map(struct s2n_config *config,
                                                     struct s2n_blob *name,
                                                     struct s2n_cert_chain_and_key *cert_key_pair)
{
    struct s2n_map *domain_name_to_cert_map = config->domain_name_to_cert_map;
    /* s2n_map does not allow zero-size key */
    if (name->size == 0) {
        return 0;
    }
    struct s2n_blob s2n_map_value = { 0 };
    s2n_authentication_method auth_method = s2n_cert_chain_and_key_get_auth_method(cert_key_pair);
    if (s2n_map_lookup(domain_name_to_cert_map, name, &s2n_map_value) == 0) {
        struct auth_method_to_cert_value value = {{ 0 }};
        value.certs[auth_method] = cert_key_pair;
        s2n_map_value.data = (uint8_t *) &value;
        s2n_map_value.size = sizeof(struct auth_method_to_cert_value);

        GUARD(s2n_map_unlock(domain_name_to_cert_map));
        GUARD(s2n_map_add(domain_name_to_cert_map, name, &s2n_map_value));
        GUARD(s2n_map_complete(domain_name_to_cert_map));
    } else {
        struct auth_method_to_cert_value *value = (void *) s2n_map_value.data;;
        if (value->certs[auth_method] == NULL) {
            value->certs[auth_method] = cert_key_pair;
        } else if (config->cert_tiebreak_cb) {
            /* There's an existing certificate for this (domain_name, auth_method).
             * Run the application's tiebreaking callback to decide which cert should be used.
             * An application may have some context specific logic to resolve ties that are based
             * on factors like trust, expiry, etc.
             */
            struct s2n_cert_chain_and_key *winner = config->cert_tiebreak_cb(
                    value->certs[auth_method],
                    cert_key_pair,
                    name->data,
                    name->size);
            if (winner) {
                value->certs[auth_method] = winner;
            }
        }
    }

    return 0;
}

static int s2n_config_build_domain_name_to_cert_map(struct s2n_config *config, struct s2n_cert_chain_and_key *cert_key_pair)
{
    if (s2n_array_num_elements(cert_key_pair->san_names) == 0) {
        for (int i = 0; i < s2n_array_num_elements(cert_key_pair->cn_names); i++) {
            struct s2n_blob *cn_name = s2n_array_get(cert_key_pair->cn_names, i);
            GUARD(s2n_config_update_domain_name_to_cert_map(config, cn_name, cert_key_pair));
        }
    } else {
        for (int i = 0; i < s2n_array_num_elements(cert_key_pair->san_names); i++) {
            struct s2n_blob *san_name = s2n_array_get(cert_key_pair->san_names, i);
            GUARD(s2n_config_update_domain_name_to_cert_map(config, san_name, cert_key_pair));
        }
    }

    return 0;
}

struct s2n_config *s2n_fetch_default_config(void)
{
    if (!default_config_init) {
        GUARD_PTR(s2n_config_init(&s2n_default_config));
        s2n_config_set_cipher_preferences(&s2n_default_config, "default");
        s2n_default_config.client_cert_auth_type = S2N_CERT_AUTH_NONE; /* Do not require the client to provide a Cert to the Server */

        default_config_init = 1;
    }

    return &s2n_default_config;
}

struct s2n_config *s2n_fetch_default_fips_config(void)
{
    if (!default_fips_config_init) {
        GUARD_PTR(s2n_config_init(&s2n_default_fips_config));
        s2n_config_set_cipher_preferences(&s2n_default_fips_config, "default_fips");

        default_fips_config_init = 1;
    }

    return &s2n_default_fips_config;
}

struct s2n_config *s2n_fetch_unsafe_client_testing_config(void)
{
    if (!unsafe_client_testing_config_init) {
        GUARD_PTR(s2n_config_init(&s2n_unsafe_client_testing_config));
        s2n_config_set_cipher_preferences(&s2n_unsafe_client_testing_config, "default");
        s2n_unsafe_client_testing_config.client_cert_auth_type = S2N_CERT_AUTH_NONE;
        s2n_unsafe_client_testing_config.check_ocsp = 0;
        s2n_unsafe_client_testing_config.disable_x509_validation = 1;

        unsafe_client_testing_config_init = 1;
    }

    return &s2n_unsafe_client_testing_config;
}

struct s2n_config *s2n_fetch_unsafe_client_ecdsa_testing_config(void)
{
    if (!unsafe_client_ecdsa_testing_config_init) {
        GUARD_PTR(s2n_config_init(&s2n_unsafe_client_ecdsa_testing_config));
        s2n_config_set_cipher_preferences(&s2n_unsafe_client_ecdsa_testing_config, "test_all_ecdsa");
        s2n_unsafe_client_ecdsa_testing_config.client_cert_auth_type = S2N_CERT_AUTH_NONE;
        s2n_unsafe_client_ecdsa_testing_config.check_ocsp = 0;
        s2n_unsafe_client_ecdsa_testing_config.disable_x509_validation = 1;

        unsafe_client_ecdsa_testing_config_init = 1;
    }

    return &s2n_unsafe_client_ecdsa_testing_config;
}

struct s2n_config *s2n_fetch_default_client_config(void)
{
    if (!default_client_config_init) {
        GUARD_PTR(s2n_config_init(&default_client_config));
        s2n_config_set_cipher_preferences(&default_client_config, "default");
        default_client_config.client_cert_auth_type = S2N_CERT_AUTH_REQUIRED;

        default_client_config_init = 1;
    }

    return &default_client_config;
}

void s2n_wipe_static_configs(void)
{
    if (default_client_config_init) {
        s2n_config_cleanup(&default_client_config);
        default_client_config_init = 0;
    }

    if (unsafe_client_testing_config_init) {
        s2n_config_cleanup(&s2n_unsafe_client_testing_config);
        unsafe_client_testing_config_init = 0;
    }

    if (unsafe_client_ecdsa_testing_config_init) {
        s2n_config_cleanup(&s2n_unsafe_client_ecdsa_testing_config);
        unsafe_client_ecdsa_testing_config_init = 0;
    }

    if (default_fips_config_init) {
        s2n_config_cleanup(&s2n_default_fips_config);
        default_fips_config_init = 0;
    }
}

struct s2n_config *s2n_config_new(void)
{
    struct s2n_blob allocator = {0};
    struct s2n_config *new_config;

    GUARD_PTR(s2n_alloc(&allocator, sizeof(struct s2n_config)));

    new_config = (struct s2n_config *)(void *)allocator.data;
    GUARD_PTR(s2n_config_init(new_config));

    return new_config;
}

static int s2n_config_store_ticket_key_comparator(const void *a, const void *b)
{
    if (((const struct s2n_ticket_key *) a)->intro_timestamp >= ((const struct s2n_ticket_key *) b)->intro_timestamp) {
        return S2N_GREATER_OR_EQUAL;
    } else {
        return S2N_LESS_THAN;
    }
}

static int s2n_verify_unique_ticket_key_comparator(const void *a, const void *b)
{
    return memcmp(a, b, SHA_DIGEST_LENGTH);
}

int s2n_config_init_session_ticket_keys(struct s2n_config *config)
{
    if (config->ticket_keys == NULL) {
      notnull_check(config->ticket_keys = s2n_set_new(sizeof(struct s2n_ticket_key), s2n_config_store_ticket_key_comparator));
    }

    if (config->ticket_key_hashes == NULL) {
      notnull_check(config->ticket_key_hashes = s2n_set_new(SHA_DIGEST_LENGTH, s2n_verify_unique_ticket_key_comparator));
    }

    return 0;
}

int s2n_config_free_session_ticket_keys(struct s2n_config *config)
{
    if (config->ticket_keys != NULL) {
        GUARD(s2n_set_free_p(&config->ticket_keys));
    }

    if (config->ticket_key_hashes != NULL) {
        GUARD(s2n_set_free_p(&config->ticket_key_hashes));
    }

    return 0;
}

int s2n_config_free_cert_chain_and_key(struct s2n_config *config)
{
    /* Free the cert_chain_and_key since the application has no reference
     * to it. This is necessary until s2n_config_add_cert_chain_and_key is deprecated. */
    if (config->cert_allocated) {
        for (int i = 0; i < S2N_AUTHENTICATION_METHOD_SENTINEL; i++) {
            s2n_cert_chain_and_key_free(config->default_cert_per_auth_method.certs[i]);
        }
    }

    return 0;
}

int s2n_config_free_dhparams(struct s2n_config *config)
{
    if (config->dhparams) {
        GUARD(s2n_dh_params_free(config->dhparams));
    }

    GUARD(s2n_free_object((uint8_t **)&config->dhparams, sizeof(struct s2n_dh_params)));
    return 0;
}

int s2n_config_free(struct s2n_config *config)
{
    s2n_config_cleanup(config);

    GUARD(s2n_free_object((uint8_t **)&config, sizeof(struct s2n_config)));
    return 0;
}

int s2n_config_get_client_auth_type(struct s2n_config *config, s2n_cert_auth_type *client_auth_type)
{
    notnull_check(config);
    notnull_check(client_auth_type);
    *client_auth_type = config->client_cert_auth_type;
    return 0;
}

int s2n_config_set_client_auth_type(struct s2n_config *config, s2n_cert_auth_type client_auth_type)
{
    notnull_check(config);
    config->client_cert_auth_type = client_auth_type;
    return 0;
}

int s2n_config_set_ct_support_level(struct s2n_config *config, s2n_ct_support_level type)
{
    notnull_check(config);
    config->ct_type = type;

    return 0;
}

int s2n_config_set_alert_behavior(struct s2n_config *config, s2n_alert_behavior alert_behavior)
{
    notnull_check(config);

    switch (alert_behavior) {
        case S2N_ALERT_FAIL_ON_WARNINGS:
        case S2N_ALERT_IGNORE_WARNINGS:
            config->alert_behavior = alert_behavior;
            break;
        default:
            S2N_ERROR(S2N_ERR_INVALID_ARGUMENT);
    }

    return 0;
}

int s2n_config_set_verify_host_callback(struct s2n_config *config, s2n_verify_host_fn verify_host_fn, void *data)
{
    notnull_check(config);
    config->verify_host = verify_host_fn;
    config->data_for_verify_host = data;
    return 0;
}

int s2n_config_set_check_stapled_ocsp_response(struct s2n_config *config, uint8_t check_ocsp)
{
    notnull_check(config);
    config->check_ocsp = check_ocsp;
    return 0;
}

int s2n_config_disable_x509_verification(struct s2n_config *config)
{
    notnull_check(config);
    s2n_x509_trust_store_wipe(&config->trust_store);
    config->disable_x509_validation = 1;
    return 0;
}

int s2n_config_set_max_cert_chain_depth(struct s2n_config *config, uint16_t max_depth)
{
    notnull_check(config);
    S2N_ERROR_IF(max_depth == 0, S2N_ERR_INVALID_ARGUMENT);

    config->max_verify_cert_chain_depth = max_depth;
    config->max_verify_cert_chain_depth_set = 1;
    return 0;
}


int s2n_config_set_status_request_type(struct s2n_config *config, s2n_status_request_type type)
{
    S2N_ERROR_IF(type == S2N_STATUS_REQUEST_OCSP && !s2n_x509_ocsp_stapling_supported(), S2N_ERR_OCSP_NOT_SUPPORTED);

    notnull_check(config);
    config->status_request_type = type;

    return 0;
}

int s2n_config_add_pem_to_trust_store(struct s2n_config *config, const char *pem)
{
    notnull_check(config);
    notnull_check(pem);

    GUARD(s2n_x509_trust_store_add_pem(&config->trust_store, pem));

    return 0;
}

int s2n_config_set_verification_ca_location(struct s2n_config *config, const char *ca_pem_filename, const char *ca_dir)
{
    notnull_check(config);
    int err_code = s2n_x509_trust_store_from_ca_file(&config->trust_store, ca_pem_filename, ca_dir);

    if (!err_code) {
        config->status_request_type = s2n_x509_ocsp_stapling_supported() ? S2N_STATUS_REQUEST_OCSP : S2N_STATUS_REQUEST_NONE;
    }

    return err_code;
}

/* Deprecated. Superseded by s2n_config_add_cert_chain_and_key_to_store */
int s2n_config_add_cert_chain_and_key(struct s2n_config *config, const char *cert_chain_pem, const char *private_key_pem)
{
    struct s2n_cert_chain_and_key *chain_and_key;
    notnull_check(chain_and_key = s2n_cert_chain_and_key_new());
    GUARD(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
    GUARD(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    config->cert_allocated = 1;

    return 0;
}

int s2n_config_add_cert_chain_and_key_to_store(struct s2n_config *config, struct s2n_cert_chain_and_key *cert_key_pair)
{
    notnull_check(config->domain_name_to_cert_map);
    notnull_check(cert_key_pair);

    GUARD(s2n_config_build_domain_name_to_cert_map(config, cert_key_pair));

    if (!config->default_certs_are_explicit) {
        /* Attempt to auto set default based on ordering. ie: first RSA cert is the default, first ECDSA cert is the
         * default, etc. */
        s2n_authentication_method cert_auth_method = s2n_cert_chain_and_key_get_auth_method(cert_key_pair);
        if (config->default_cert_per_auth_method.certs[cert_auth_method] == NULL) {
            config->default_cert_per_auth_method.certs[cert_auth_method] = cert_key_pair;
        }
    }

    return 0;
}

int s2n_config_clear_default_certificates(struct s2n_config *config)
{
    notnull_check(config);
    for (int i = 0; i < S2N_AUTHENTICATION_METHOD_SENTINEL; i++) {
        config->default_cert_per_auth_method.certs[i] = NULL;
    }
    return 0;
}

int s2n_config_set_cert_chain_and_key_defaults(struct s2n_config *config,
                                               struct s2n_cert_chain_and_key **cert_key_pairs,
                                               uint32_t num_cert_key_pairs)
{
    notnull_check(config);
    notnull_check(cert_key_pairs);
    S2N_ERROR_IF(num_cert_key_pairs < 1 || num_cert_key_pairs > S2N_AUTHENTICATION_METHOD_SENTINEL,
            S2N_ERR_NUM_DEFAULT_CERTIFICATES);

    /* Validate certs being set before clearing auto-chosen defaults or previously set defaults */
    struct auth_method_to_cert_value new_defaults = {{ 0 }};
    for (int i = 0; i < num_cert_key_pairs; i++) {
        notnull_check(cert_key_pairs[i]);
        s2n_authentication_method auth_method = s2n_cert_chain_and_key_get_auth_method(cert_key_pairs[i]);
        S2N_ERROR_IF(new_defaults.certs[auth_method] != NULL, S2N_ERR_MULTIPLE_DEFAULT_CERTIFICATES_PER_AUTH_TYPE);
        new_defaults.certs[auth_method] = cert_key_pairs[i];
    }

    GUARD(s2n_config_clear_default_certificates(config));
    for (int i = 0; i < num_cert_key_pairs; i++) {
        s2n_authentication_method auth_method = s2n_cert_chain_and_key_get_auth_method(cert_key_pairs[i]);
        config->default_cert_per_auth_method.certs[auth_method] = cert_key_pairs[i];
    }

    config->default_certs_are_explicit = 1;
    return 0;
}

int s2n_config_add_dhparams(struct s2n_config *config, const char *dhparams_pem)
{
    DEFER_CLEANUP(struct s2n_stuffer dhparams_in_stuffer = {0}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer dhparams_out_stuffer = {0}, s2n_stuffer_free);
    struct s2n_blob dhparams_blob = {0};
    struct s2n_blob mem = {0};

    /* Allocate the memory for the chain and key struct */
    GUARD(s2n_alloc(&mem, sizeof(struct s2n_dh_params)));
    config->dhparams = (struct s2n_dh_params *)(void *)mem.data;

    GUARD(s2n_stuffer_alloc_ro_from_string(&dhparams_in_stuffer, dhparams_pem));
    GUARD(s2n_stuffer_growable_alloc(&dhparams_out_stuffer, strlen(dhparams_pem)));

    /* Convert pem to asn1 and asn1 to the private key */
    GUARD(s2n_stuffer_dhparams_from_pem(&dhparams_in_stuffer, &dhparams_out_stuffer));

    dhparams_blob.size = s2n_stuffer_data_available(&dhparams_out_stuffer);
    dhparams_blob.data = s2n_stuffer_raw_read(&dhparams_out_stuffer, dhparams_blob.size);
    notnull_check(dhparams_blob.data);

    GUARD(s2n_pkcs3_to_dh_params(config->dhparams, &dhparams_blob));

    return 0;
}

extern int s2n_config_set_wall_clock(struct s2n_config *config, s2n_clock_time_nanoseconds clock_fn, void *ctx)
{
    notnull_check(clock_fn);

    config->wall_clock = clock_fn;
    config->sys_clock_ctx = ctx;

    return 0;
}

extern int s2n_config_set_monotonic_clock(struct s2n_config *config, s2n_clock_time_nanoseconds clock_fn, void *ctx)
{
    notnull_check(clock_fn);

    config->monotonic_clock = clock_fn;
    config->monotonic_clock_ctx = ctx;

    return 0;
}

int s2n_config_set_cache_store_callback(struct s2n_config *config, s2n_cache_store_callback cache_store_callback, void *data)
{
    notnull_check(cache_store_callback);

    config->cache_store = cache_store_callback;
    config->cache_store_data = data;

    return 0;
}

int s2n_config_set_cache_retrieve_callback(struct s2n_config *config, s2n_cache_retrieve_callback cache_retrieve_callback, void *data)
{
    notnull_check(cache_retrieve_callback);

    config->cache_retrieve = cache_retrieve_callback;
    config->cache_retrieve_data = data;

    return 0;
}

int s2n_config_set_cache_delete_callback(struct s2n_config *config, s2n_cache_delete_callback cache_delete_callback, void *data)
{
    notnull_check(cache_delete_callback);

    config->cache_delete = cache_delete_callback;
    config->cache_delete_data = data;

    return 0;
}

int s2n_config_set_extension_data(struct s2n_config *config, s2n_tls_extension_type type, const uint8_t *data, uint32_t length)
{
    notnull_check(config);

    if (s2n_config_get_num_default_certs(config) == 0) {
        S2N_ERROR(S2N_ERR_UPDATING_EXTENSION);
    }
    struct s2n_cert_chain_and_key *config_chain_and_key = s2n_config_get_single_default_cert(config);
    notnull_check(config_chain_and_key);

    switch (type) {
        case S2N_EXTENSION_CERTIFICATE_TRANSPARENCY:
            {
                GUARD(s2n_cert_chain_and_key_set_sct_list(config_chain_and_key, data, length));
            } break;
        case S2N_EXTENSION_OCSP_STAPLING:
            {
                GUARD(s2n_cert_chain_and_key_set_ocsp_data(config_chain_and_key, data, length));
            } break;
        default:
            S2N_ERROR(S2N_ERR_UNRECOGNIZED_EXTENSION);
    }

    return 0;
}

int s2n_config_set_client_hello_cb(struct s2n_config *config, s2n_client_hello_fn client_hello_cb, void *ctx)
{
    config->client_hello_cb = client_hello_cb;
    config->client_hello_cb_ctx = ctx;

    return 0;
}

int s2n_config_send_max_fragment_length(struct s2n_config *config, s2n_max_frag_len mfl_code)
{
    notnull_check(config);

    S2N_ERROR_IF(mfl_code > S2N_TLS_MAX_FRAG_LEN_4096, S2N_ERR_INVALID_MAX_FRAG_LEN);

    config->mfl_code = mfl_code;

    return 0;
}

int s2n_config_accept_max_fragment_length(struct s2n_config *config)
{
    notnull_check(config);

    config->accept_mfl = 1;

    return 0;
}

int s2n_config_set_session_state_lifetime(struct s2n_config *config,
                                          uint64_t lifetime_in_secs)
{
    notnull_check(config);

    config->session_state_lifetime_in_nanos = (lifetime_in_secs * ONE_SEC_IN_NANOS);
    return 0;
}

int s2n_config_set_session_tickets_onoff(struct s2n_config *config, uint8_t enabled)
{
    notnull_check(config);

    if (config->use_tickets == enabled) {
        return 0;
    }

    config->use_tickets = enabled;

    if (enabled) {
        GUARD(s2n_config_init_session_ticket_keys(config));
    } else {
        GUARD(s2n_config_free_session_ticket_keys(config));
    }

    return 0;
}

int s2n_config_set_ticket_encrypt_decrypt_key_lifetime(struct s2n_config *config,
                                                       uint64_t lifetime_in_secs)
{
    notnull_check(config);

    config->encrypt_decrypt_key_lifetime_in_nanos = (lifetime_in_secs * ONE_SEC_IN_NANOS);
    return 0;
}

int s2n_config_set_ticket_decrypt_key_lifetime(struct s2n_config *config,
                                               uint64_t lifetime_in_secs)
{
    notnull_check(config);

    config->decrypt_key_lifetime_in_nanos = (lifetime_in_secs * ONE_SEC_IN_NANOS);
    return 0;
}

int s2n_config_add_ticket_crypto_key(struct s2n_config *config,
                                     const uint8_t *name, uint32_t name_len,
                                     uint8_t *key, uint32_t key_len,
                                     uint64_t intro_time_in_seconds_from_epoch)
{
    notnull_check(config);
    notnull_check(name);
    notnull_check(key);

    if (!config->use_tickets) {
        return 0;
    }

    GUARD(s2n_config_wipe_expired_ticket_crypto_keys(config, -1));

    S2N_ERROR_IF(key_len == 0, S2N_ERR_INVALID_TICKET_KEY_LENGTH);

    S2N_ERROR_IF(s2n_set_size(config->ticket_keys) >= S2N_MAX_TICKET_KEYS, S2N_ERR_TICKET_KEY_LIMIT);

    S2N_ERROR_IF(name_len == 0 || name_len > S2N_TICKET_KEY_NAME_LEN || s2n_find_ticket_key(config, name), S2N_ERR_INVALID_TICKET_KEY_NAME_OR_NAME_LENGTH);

    uint8_t output_pad[S2N_AES256_KEY_LEN + S2N_TICKET_AAD_IMPLICIT_LEN];
    struct s2n_blob out_key = { .data = output_pad, .size = sizeof(output_pad) };
    struct s2n_blob in_key = { .data = key, .size = key_len };
    struct s2n_blob salt = { .size = 0 };
    struct s2n_blob info = { .size = 0 };

    struct s2n_ticket_key *session_ticket_key;
    DEFER_CLEANUP(struct s2n_blob allocator = {0}, s2n_free);
    GUARD(s2n_alloc(&allocator, sizeof(struct s2n_ticket_key)));
    session_ticket_key = (struct s2n_ticket_key *) (void *) allocator.data;

    DEFER_CLEANUP(struct s2n_hmac_state hmac = {0}, s2n_hmac_free);

    GUARD(s2n_hmac_new(&hmac));
    GUARD(s2n_hkdf(&hmac, S2N_HMAC_SHA256, &salt, &in_key, &info, &out_key));

    DEFER_CLEANUP(struct s2n_hash_state hash = {0}, s2n_hash_free);
    uint8_t hash_output[SHA_DIGEST_LENGTH];

    GUARD(s2n_hash_new(&hash));
    GUARD(s2n_hash_init(&hash, S2N_HASH_SHA1));
    GUARD(s2n_hash_update(&hash, out_key.data, out_key.size));
    GUARD(s2n_hash_digest(&hash, hash_output, SHA_DIGEST_LENGTH));

    if (s2n_set_size(config->ticket_key_hashes) >= S2N_MAX_TICKET_KEY_HASHES) {
        GUARD(s2n_set_free_p(&config->ticket_key_hashes));
        notnull_check(config->ticket_key_hashes = s2n_set_new(SHA_DIGEST_LENGTH, s2n_verify_unique_ticket_key_comparator));
    }

    /* Insert hash key into a sorted array at known index */
    GUARD(s2n_set_add(config->ticket_key_hashes, hash_output));

    memcpy_check(session_ticket_key->key_name, name, S2N_TICKET_KEY_NAME_LEN);
    memcpy_check(session_ticket_key->aes_key, out_key.data, S2N_AES256_KEY_LEN);
    out_key.data = output_pad + S2N_AES256_KEY_LEN;
    memcpy_check(session_ticket_key->implicit_aad, out_key.data, S2N_TICKET_AAD_IMPLICIT_LEN);

    if (intro_time_in_seconds_from_epoch == 0) {
        uint64_t now;
        GUARD(config->wall_clock(config->sys_clock_ctx, &now));
        session_ticket_key->intro_timestamp = now;
    } else {
        session_ticket_key->intro_timestamp = (intro_time_in_seconds_from_epoch * ONE_SEC_IN_NANOS);
    }

    GUARD(s2n_config_store_ticket_key(config, session_ticket_key));

    return 0;
}

int s2n_config_set_cert_tiebreak_callback(struct s2n_config *config, s2n_cert_tiebreak_callback cert_tiebreak_cb)
{
    config->cert_tiebreak_cb = cert_tiebreak_cb;
    return 0;
}

struct s2n_cert_chain_and_key *s2n_config_get_single_default_cert(struct s2n_config *config)
{
    notnull_check_ptr(config);
    struct s2n_cert_chain_and_key *cert = NULL;

    for (int i = S2N_AUTHENTICATION_METHOD_SENTINEL - 1; i >= 0; i--) {
        if (config->default_cert_per_auth_method.certs[i] != NULL) {
            cert = config->default_cert_per_auth_method.certs[i];
        }
    }
    return cert;
}

int s2n_config_get_num_default_certs(struct s2n_config *config)
{
    notnull_check(config);
    int num_certs = 0;
    for (int i = 0; i < S2N_AUTHENTICATION_METHOD_SENTINEL; i++) {
        if (config->default_cert_per_auth_method.certs[i] != NULL) {
            num_certs++;
        }
    }

    return num_certs;
}
