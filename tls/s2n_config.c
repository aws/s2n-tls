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

#include <strings.h>
#include <time.h>

#include "error/s2n_errno.h"

#include "crypto/s2n_fips.h"

#include "tls/s2n_cipher_preferences.h"
#include "utils/s2n_safety.h"
#include "crypto/s2n_hkdf.h"

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
    config->cert_and_key_pairs = NULL;
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

    if (s2n_is_in_fips_mode()) {
        s2n_config_set_cipher_preferences(config, "default_fips");
    } else {
        s2n_config_set_cipher_preferences(config, "default");
    }

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

    return 0;
}

struct s2n_config *s2n_fetch_default_config(void) {
    if (!default_config_init) {
        s2n_config_init(&s2n_default_config);
        s2n_default_config.cert_and_key_pairs = NULL;
        s2n_default_config.cipher_preferences = &cipher_preferences_20170210;
        s2n_default_config.client_cert_auth_type = S2N_CERT_AUTH_NONE; /* Do not require the client to provide a Cert to the Server */
        s2n_default_config.data_for_verify_host = NULL;

        default_config_init = 1;
    }

    return &s2n_default_config;
}

struct s2n_config *s2n_fetch_default_fips_config(void)
{
    if (!default_fips_config_init) {
        s2n_config_init(&s2n_default_fips_config);
        s2n_default_fips_config.cert_and_key_pairs = NULL;
        s2n_default_fips_config.cipher_preferences = &cipher_preferences_20170405;

        default_fips_config_init = 1;
    }

    return &s2n_default_fips_config;
}

struct s2n_config *s2n_fetch_unsafe_client_testing_config(void)
{
    if (!unsafe_client_testing_config_init) {
        s2n_config_init(&s2n_unsafe_client_testing_config);
        s2n_unsafe_client_testing_config.cert_and_key_pairs = NULL;
        s2n_unsafe_client_testing_config.cipher_preferences = &cipher_preferences_20170210;
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
        s2n_config_init(&s2n_unsafe_client_ecdsa_testing_config);
        s2n_unsafe_client_ecdsa_testing_config.cert_and_key_pairs = NULL;
        s2n_unsafe_client_ecdsa_testing_config.cipher_preferences = &cipher_preferences_test_all_ecdsa;
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
        s2n_config_init(&default_client_config);
        default_client_config.cert_and_key_pairs = NULL;
        default_client_config.cipher_preferences = &cipher_preferences_20170210;
        default_client_config.client_cert_auth_type = S2N_CERT_AUTH_REQUIRED;

        default_client_config_init = 1;
    }

    return &default_client_config;
}

void s2n_wipe_static_configs(void) {
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
    s2n_config_init(new_config);

    return new_config;
}

int s2n_config_init_session_ticket_keys(struct s2n_config *config)
{
    if (config->ticket_keys == NULL) {
        notnull_check(config->ticket_keys = s2n_array_new(sizeof(struct s2n_ticket_key)));
    }

    if (config->ticket_key_hashes == NULL) {
        notnull_check(config->ticket_key_hashes = s2n_array_new(SHA_DIGEST_LENGTH));
    }

    return 0;
}

int s2n_config_free_session_ticket_keys(struct s2n_config *config)
{
    if (config->ticket_keys != NULL) {
        GUARD(s2n_array_free(config->ticket_keys));
        config->ticket_keys = NULL;
    }

    if (config->ticket_key_hashes != NULL) {
        GUARD(s2n_array_free(config->ticket_key_hashes));
        config->ticket_key_hashes = NULL;
    }

    return 0;
}

int s2n_config_free_cert_chain_and_key(struct s2n_config *config)
{

    struct s2n_blob b = {
        .data = (uint8_t *) config->cert_and_key_pairs,
        .size = sizeof(struct s2n_cert_chain_and_key)
    };

    /* If there were cert and key pairs set, walk the chain and free the certs */
    if (config->cert_and_key_pairs) {
        struct s2n_cert *node = config->cert_and_key_pairs->cert_chain.head;
        while (node) {
            struct s2n_blob n = {
                .data = (uint8_t *) node,
                .size = sizeof(struct s2n_cert)
            };
            /* Free the cert */
            GUARD(s2n_free(&node->raw));
            /* Advance to next */
            node = node->next;
            /* Free the node */
            GUARD(s2n_free(&n));
        }
        GUARD(s2n_pkey_free(&config->cert_and_key_pairs->private_key));
        GUARD(s2n_free(&config->cert_and_key_pairs->ocsp_status));
        GUARD(s2n_free(&config->cert_and_key_pairs->sct_list));
    }

    GUARD(s2n_free(&b));
    return 0;
}

int s2n_config_free_dhparams(struct s2n_config *config)
{
    struct s2n_blob b = {
        .data = (uint8_t *) config->dhparams,
        .size = sizeof(struct s2n_dh_params)
    };

    if (config->dhparams) {
        GUARD(s2n_dh_params_free(config->dhparams));
    }

    GUARD(s2n_free(&b));
    return 0;
}

int s2n_config_free(struct s2n_config *config)
{
    struct s2n_blob b = {.data = (uint8_t *) config,.size = sizeof(struct s2n_config) };

    s2n_config_cleanup(config);

    GUARD(s2n_free(&b));
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

int s2n_config_set_max_cert_chain_depth(struct s2n_config *config, uint16_t max_depth) {
    notnull_check(config);

    if (max_depth > 0) {
        config->max_verify_cert_chain_depth = max_depth;
        config->max_verify_cert_chain_depth_set = 1;
        return 0;
    }

    return -1;
}


int s2n_config_set_status_request_type(struct s2n_config *config, s2n_status_request_type type)
{
    if (type == S2N_STATUS_REQUEST_OCSP && !s2n_x509_ocsp_stapling_supported()) {
        return -1;
    }

    notnull_check(config);
    config->status_request_type = type;

    return 0;
}

int s2n_config_add_pem_to_trust_store(struct s2n_config *config, const char *pem){
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

int s2n_config_add_cert_chain_from_stuffer(struct s2n_config *config, struct s2n_stuffer *chain_in_stuffer)
{
    DEFER_CLEANUP(struct s2n_stuffer cert_out_stuffer = {{0}}, s2n_stuffer_free);
    GUARD(s2n_stuffer_growable_alloc(&cert_out_stuffer, 2048));

    struct s2n_cert **insert = &config->cert_and_key_pairs->cert_chain.head;
    uint32_t chain_size = 0;
    do {
        struct s2n_cert *new_node;

        if (s2n_stuffer_certificate_from_pem(chain_in_stuffer, &cert_out_stuffer) < 0) {
            if (chain_size == 0) {
                S2N_ERROR(S2N_ERR_NO_CERTIFICATE_IN_PEM);
            }
            break;
        }
        struct s2n_blob mem = {0};
        GUARD(s2n_alloc(&mem, sizeof(struct s2n_cert)));
        new_node = (struct s2n_cert *)(void *)mem.data;

        GUARD(s2n_alloc(&new_node->raw, s2n_stuffer_data_available(&cert_out_stuffer)));
        GUARD(s2n_stuffer_read(&cert_out_stuffer, &new_node->raw));

        /* Additional 3 bytes for the length field in the protocol */
        chain_size += new_node->raw.size + 3;
        new_node->next = NULL;
        *insert = new_node;
        insert = &new_node->next;
    } while (s2n_stuffer_data_available(chain_in_stuffer));

    /* Leftover data at this point means one of two things:
     * A bug in s2n's PEM parsing OR a malformed PEM in the user's chain.
     * Be conservative and fail instead of using a partial chain.
     */
    S2N_ERROR_IF(s2n_stuffer_data_available(chain_in_stuffer) > 0, S2N_ERR_INVALID_PEM);
    config->cert_and_key_pairs->cert_chain.chain_size = chain_size;

    return 0;
}

int s2n_config_add_cert_chain(struct s2n_config *config, const char *cert_chain_pem)
{
    struct s2n_stuffer chain_in_stuffer = {{0}};

    /* Turn the chain into a stuffer */
    GUARD(s2n_stuffer_alloc_ro_from_string(&chain_in_stuffer, cert_chain_pem));
    int rc = s2n_config_add_cert_chain_from_stuffer(config, &chain_in_stuffer);

    GUARD(s2n_stuffer_free(&chain_in_stuffer));

    return rc;
}

int s2n_config_add_private_key(struct s2n_config *config, const char *private_key_pem)
{
    DEFER_CLEANUP(struct s2n_stuffer key_in_stuffer = {{0}}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer key_out_stuffer = {{0}}, s2n_stuffer_free);
    struct s2n_blob key_blob = {0};

    GUARD(s2n_pkey_zero_init(&config->cert_and_key_pairs->private_key));

    /* Put the private key pem in a stuffer */
    GUARD(s2n_stuffer_alloc_ro_from_string(&key_in_stuffer, private_key_pem));
    GUARD(s2n_stuffer_growable_alloc(&key_out_stuffer, strlen(private_key_pem)));

    /* Convert pem to asn1 and asn1 to the private key. Handles both PKCS#1 and PKCS#8 formats */
    GUARD(s2n_stuffer_private_key_from_pem(&key_in_stuffer, &key_out_stuffer));
    key_blob.size = s2n_stuffer_data_available(&key_out_stuffer);
    key_blob.data = s2n_stuffer_raw_read(&key_out_stuffer, key_blob.size);
    notnull_check(key_blob.data);

    /* Get key type and create appropriate key context */
    GUARD(s2n_asn1der_to_private_key(&config->cert_and_key_pairs->private_key, &key_blob));

    return 0;
}

int s2n_config_add_cert_chain_and_key(struct s2n_config *config, const char *cert_chain_pem, const char *private_key_pem)
{
    struct s2n_blob mem = {0};

    /* Allocate the memory for the chain and key struct */
    GUARD(s2n_alloc(&mem, sizeof(struct s2n_cert_chain_and_key)));
    config->cert_and_key_pairs = (struct s2n_cert_chain_and_key *)(void *)mem.data;
    config->cert_and_key_pairs->cert_chain.head = NULL;

    memset(&config->cert_and_key_pairs->ocsp_status, 0, sizeof(config->cert_and_key_pairs->ocsp_status));
    memset(&config->cert_and_key_pairs->sct_list, 0, sizeof(config->cert_and_key_pairs->sct_list));
    GUARD(s2n_pkey_zero_init(&config->cert_and_key_pairs->private_key));

    GUARD(s2n_config_add_cert_chain(config, cert_chain_pem));
    GUARD(s2n_config_add_private_key(config, private_key_pem));

    /* Parse the leaf cert for the public key and certificate type */
    DEFER_CLEANUP(struct s2n_pkey public_key = {{{0}}}, s2n_pkey_free);
    s2n_cert_type cert_type;
    GUARD(s2n_asn1der_to_public_key_and_type(&public_key, &cert_type, &config->cert_and_key_pairs->cert_chain.head->raw));
    GUARD(s2n_cert_set_cert_type(config->cert_and_key_pairs->cert_chain.head, cert_type));

    /* Validate the leaf cert's public key matches the provided private key */
    GUARD(s2n_pkey_match(&public_key, &config->cert_and_key_pairs->private_key));

    return 0;
}

int s2n_config_add_dhparams(struct s2n_config *config, const char *dhparams_pem)
{
    DEFER_CLEANUP(struct s2n_stuffer dhparams_in_stuffer = {{0}}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer dhparams_out_stuffer = {{0}}, s2n_stuffer_free);
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

int s2n_config_set_cache_store_callback(struct s2n_config *config,
                                        int (*cache_store) (void *, uint64_t ttl_in_seconds, const void *key, uint64_t key_size, const void *value, uint64_t value_size),
                                        void *data)
{
    notnull_check(cache_store);

    config->cache_store = cache_store;
    config->cache_store_data = data;

    return 0;
}

int s2n_config_set_cache_retrieve_callback(struct s2n_config *config, int (*cache_retrieve) (void *, const void *key, uint64_t key_size, void *value, uint64_t * value_size),
                                           void *data)
{
    notnull_check(cache_retrieve);

    config->cache_retrieve = cache_retrieve;
    config->cache_retrieve_data = data;

    return 0;
}

int s2n_config_set_cache_delete_callback(struct s2n_config *config, int (*cache_delete) (void *, const void *key, uint64_t key_size), void *data)
{
    notnull_check(cache_delete);

    config->cache_delete = cache_delete;
    config->cache_delete_data = data;

    return 0;
}

int s2n_config_set_extension_data(struct s2n_config *config, s2n_tls_extension_type type, const uint8_t *data, uint32_t length)
{
    notnull_check(config);

    switch (type) {
        case S2N_EXTENSION_CERTIFICATE_TRANSPARENCY:
            {
                GUARD(s2n_free(&config->cert_and_key_pairs->sct_list));

                if (data && length) {
                    GUARD(s2n_alloc(&config->cert_and_key_pairs->sct_list, length));
                    memcpy_check(config->cert_and_key_pairs->sct_list.data, data, length);
                }
            } break;
        case S2N_EXTENSION_OCSP_STAPLING:
            {
                GUARD(s2n_free(&config->cert_and_key_pairs->ocsp_status));

                if (data && length) {
                    GUARD(s2n_alloc(&config->cert_and_key_pairs->ocsp_status, length));
                    memcpy_check(config->cert_and_key_pairs->ocsp_status.data, data, length);
                }
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

int s2n_config_get_cert_type(struct s2n_config *config, s2n_cert_type *cert_type)
{
    notnull_check(config);
    notnull_check(config->cert_and_key_pairs);
    notnull_check(config->cert_and_key_pairs->cert_chain.head);

    *cert_type = config->cert_and_key_pairs->cert_chain.head->cert_type;

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

    S2N_ERROR_IF(config->ticket_keys->num_of_elements >= S2N_MAX_TICKET_KEYS, S2N_ERR_TICKET_KEY_LIMIT);

    S2N_ERROR_IF(name_len == 0 || name_len > S2N_TICKET_KEY_NAME_LEN || s2n_find_ticket_key(config, name), S2N_ERR_INVALID_TICKET_KEY_NAME_OR_NAME_LENGTH);

    uint64_t now;
    uint16_t insert_index = 0;
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

    if (config->ticket_key_hashes->num_of_elements >= S2N_MAX_TICKET_KEY_HASHES) {
        GUARD(s2n_array_free(config->ticket_key_hashes));
        notnull_check(config->ticket_key_hashes = s2n_array_new(SHA_DIGEST_LENGTH));
    }

    S2N_ERROR_IF(s2n_verify_unique_ticket_key(config, hash_output, &insert_index) < 0, S2N_ERR_TICKET_KEY_NOT_UNIQUE);

    /* Insert hash key into a sorted array at known index */
    struct uint8_t *hash_element = s2n_array_insert(config->ticket_key_hashes, insert_index);
    memcpy_check(hash_element, hash_output, SHA_DIGEST_LENGTH);

    memcpy_check(session_ticket_key->key_name, name, S2N_TICKET_KEY_NAME_LEN);
    memcpy_check(session_ticket_key->aes_key, out_key.data, S2N_AES256_KEY_LEN);
    out_key.data = output_pad + S2N_AES256_KEY_LEN;
    memcpy_check(session_ticket_key->implicit_aad, out_key.data, S2N_TICKET_AAD_IMPLICIT_LEN);

    if (intro_time_in_seconds_from_epoch == 0) {
        GUARD(config->monotonic_clock(config->monotonic_clock_ctx, &now));
        session_ticket_key->intro_timestamp = now;
    } else {
        session_ticket_key->intro_timestamp = (intro_time_in_seconds_from_epoch * ONE_SEC_IN_NANOS);
    }

    GUARD(s2n_config_store_ticket_key(config, session_ticket_key));

    return 0;
}
