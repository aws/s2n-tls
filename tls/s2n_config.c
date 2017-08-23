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

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_config.h"

#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"
#include "tls/s2n_tls_parameters.h"

#if defined(__APPLE__) && defined(__MACH__)

#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/mach_time.h>

int get_nanoseconds_since_epoch(void *data, uint64_t * nanoseconds)
{
    mach_timebase_info_data_t conversion_factor;

    GUARD(mach_timebase_info(&conversion_factor));

    *nanoseconds = mach_absolute_time();
    *nanoseconds *= conversion_factor.numer;
    *nanoseconds /= conversion_factor.denom;

    return 0;
}

#else

#include <time.h>

#if defined(CLOCK_MONOTONIC_RAW)
#define S2N_CLOCK CLOCK_MONOTONIC_RAW
#else
#define S2N_CLOCK CLOCK_MONOTONIC
#endif

int get_nanoseconds_since_epoch(void *data, uint64_t * nanoseconds)
{
    struct timespec current_time;

    GUARD(clock_gettime(S2N_CLOCK, &current_time));

    *nanoseconds = current_time.tv_sec * 1000000000;
    *nanoseconds += current_time.tv_nsec;

    return 0;
}

#endif

int deny_all_certs(uint8_t *cert_chain_in, uint32_t cert_chain_len, struct s2n_cert_public_key *public_key, void *context)
{
    S2N_ERROR(S2N_ERR_CERT_UNTRUSTED);
}

/* Accept all RSA Certificates is unsafe and is only used in the s2n Client for testing purposes */
s2n_cert_validation_code accept_all_rsa_certs(uint8_t *cert_chain_in, uint32_t cert_chain_len, struct s2n_cert_public_key *public_key_out, void *context)
{
    struct s2n_blob cert_chain_blob = { .data = cert_chain_in, .size = cert_chain_len};
    struct s2n_stuffer cert_chain_in_stuffer;
    if (s2n_stuffer_init(&cert_chain_in_stuffer, &cert_chain_blob) < 0) {
        return S2N_CERT_ERR_INVALID;
    }
    if (s2n_stuffer_write(&cert_chain_in_stuffer, &cert_chain_blob) < 0) {
        return S2N_CERT_ERR_INVALID;
    }

    uint32_t certificate_count = 0;
    while (s2n_stuffer_data_available(&cert_chain_in_stuffer)) {
        uint32_t certificate_size;

        if (s2n_stuffer_read_uint24(&cert_chain_in_stuffer, &certificate_size) < 0) {
            return S2N_CERT_ERR_INVALID;
        }

        if (certificate_size == 0 || certificate_size > s2n_stuffer_data_available(&cert_chain_in_stuffer) ) {
            return S2N_CERT_ERR_INVALID;
        }

        struct s2n_blob asn1cert;
        asn1cert.data = s2n_stuffer_raw_read(&cert_chain_in_stuffer, certificate_size);
        asn1cert.size = certificate_size;
        if (asn1cert.data == NULL) {
            return S2N_CERT_ERR_INVALID;
        }

        /* Pull the public key from the first certificate */
        if (certificate_count == 0) {
            struct s2n_rsa_public_key *rsa_pub_key_out;
            if (s2n_cert_public_key_get_rsa(public_key_out, &rsa_pub_key_out) < 0) {
                return S2N_CERT_ERR_INVALID;
            }
            /* Assume that the asn1cert is an RSA Cert */
            if (s2n_asn1der_to_rsa_public_key(rsa_pub_key_out, &asn1cert) < 0) {
                return S2N_CERT_ERR_INVALID;
            }
            if (s2n_cert_public_key_set_cert_type(public_key_out, S2N_CERT_TYPE_RSA_SIGN) < 0){
                return S2N_CERT_ERR_INVALID;
            }
        }

        certificate_count++;
    }

    if (certificate_count < 1) {
        return S2N_CERT_ERR_INVALID;
    }
    return 0;
}

struct s2n_config s2n_default_config = {
    .cert_and_key_pairs = NULL,
    .cipher_preferences = &cipher_preferences_20170210,
    .nanoseconds_since_epoch = get_nanoseconds_since_epoch,
    .client_cert_auth_type = S2N_CERT_AUTH_NONE, /* Do not require the client to provide a Cert to the Server */
    .verify_cert_chain_cb = deny_all_certs,
    .verify_cert_context = NULL,
};

/* This config should only used by the s2n_client for unit/integration testing purposes. */
struct s2n_config s2n_unsafe_client_testing_config = {
    .cert_and_key_pairs = NULL,
    .cipher_preferences = &cipher_preferences_20170210,
    .nanoseconds_since_epoch = get_nanoseconds_since_epoch,
    .client_cert_auth_type = S2N_CERT_AUTH_NONE,
    .verify_cert_chain_cb = accept_all_rsa_certs,
    .verify_cert_context = NULL,
};

struct s2n_config *s2n_config_new(void)
{
    struct s2n_blob allocator;
    struct s2n_config *new_config;

    GUARD_PTR(s2n_alloc(&allocator, sizeof(struct s2n_config)));

    new_config = (struct s2n_config *)(void *)allocator.data;
    new_config->cert_and_key_pairs = NULL;
    new_config->dhparams = NULL;
    new_config->application_protocols.data = NULL;
    new_config->application_protocols.size = 0;
    new_config->status_request_type = S2N_STATUS_REQUEST_NONE;
    new_config->nanoseconds_since_epoch = get_nanoseconds_since_epoch;
    new_config->client_hello_cb = NULL;
    new_config->client_hello_cb_ctx = NULL;
    new_config->cache_store = NULL;
    new_config->cache_store_data = NULL;
    new_config->cache_retrieve = NULL;
    new_config->cache_retrieve_data = NULL;
    new_config->cache_delete = NULL;
    new_config->cache_delete_data = NULL;
    new_config->ct_type = S2N_CT_SUPPORT_NONE;
    new_config->mfl_code = S2N_TLS_MAX_FRAG_LEN_EXT_NONE;
    new_config->accept_mfl = 0;

    /* By default, only the client will authenticate the Server's Certificate. The Server does not request or
     * authenticate any client certificates. */
    new_config->client_cert_auth_type = S2N_CERT_AUTH_NONE;
    new_config->verify_cert_chain_cb = deny_all_certs;
    new_config->verify_cert_context = NULL;

    GUARD_PTR(s2n_config_set_cipher_preferences(new_config, "default"));

    return new_config;
}

int s2n_config_free_cert_chain_and_key(struct s2n_config *config)
{
    struct s2n_blob b = {
        .data = (uint8_t *) config->cert_and_key_pairs,
        .size = sizeof(struct s2n_cert_chain_and_key)
    };

    /* If there were cert and key pairs set, walk the chain and free the certs */
    if (config->cert_and_key_pairs) {
        struct s2n_cert_chain *node = config->cert_and_key_pairs->head;
        while (node) {
            struct s2n_blob n = {
                .data = (uint8_t *) node,
                .size = sizeof(struct s2n_cert_chain)
            };
            /* Free the cert */
            GUARD(s2n_free(&node->cert));
            /* Advance to next */
            node = node->next;
            /* Free the node */
            GUARD(s2n_free(&n));
        }
        GUARD(s2n_rsa_private_key_free(&config->cert_and_key_pairs->private_key));
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

    GUARD(s2n_config_free_cert_chain_and_key(config));
    GUARD(s2n_config_free_dhparams(config));
    GUARD(s2n_free(&config->application_protocols));

    GUARD(s2n_free(&b));
    return 0;
}

int s2n_config_set_protocol_preferences(struct s2n_config *config, const char *const *protocols, int protocol_count)
{
    struct s2n_stuffer protocol_stuffer;

    GUARD(s2n_free(&config->application_protocols));

    if (protocols == NULL || protocol_count == 0) {
        /* NULL value indicates no preference, so nothing to do */
        return 0;
    }

    GUARD(s2n_stuffer_growable_alloc(&protocol_stuffer, 256));
    for (int i = 0; i < protocol_count; i++) {
        size_t length = strlen(protocols[i]);
        uint8_t protocol[255];

        if (length > 255 || (s2n_stuffer_data_available(&protocol_stuffer) + length + 1) > 65535) {
            S2N_ERROR(S2N_ERR_APPLICATION_PROTOCOL_TOO_LONG);
        }
        memcpy_check(protocol, protocols[i], length);
        GUARD(s2n_stuffer_write_uint8(&protocol_stuffer, length));
        GUARD(s2n_stuffer_write_bytes(&protocol_stuffer, protocol, length));
    }

    uint32_t size = s2n_stuffer_data_available(&protocol_stuffer);
    /* config->application_protocols blob now owns this data */
    config->application_protocols.size = size;
    config->application_protocols.data = s2n_stuffer_raw_read(&protocol_stuffer, size);
    notnull_check(config->application_protocols.data);

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

int s2n_config_set_verify_cert_chain_cb(struct s2n_config *config, verify_cert_trust_chain_fn *callback, void *context)
{
    notnull_check(config);
    notnull_check(callback);

    config->verify_cert_chain_cb = callback;
    config->verify_cert_context = context;

    return 0;
}

int s2n_config_set_ct_support_level(struct s2n_config *config, s2n_ct_support_level type)
{
    config->ct_type = type;

    return 0;
}


int s2n_config_set_status_request_type(struct s2n_config *config, s2n_status_request_type type)
{
    config->status_request_type = type;

    return 0;
}

int s2n_config_add_cert_chain_and_key(struct s2n_config *config, const char *cert_chain_pem, const char *private_key_pem)
{
    struct s2n_stuffer chain_in_stuffer, cert_out_stuffer, key_in_stuffer, key_out_stuffer;
    struct s2n_blob key_blob;
    struct s2n_blob mem;

    /* Allocate the memory for the chain and key struct */
    GUARD(s2n_alloc(&mem, sizeof(struct s2n_cert_chain_and_key)));
    config->cert_and_key_pairs = (struct s2n_cert_chain_and_key *)(void *)mem.data;
    config->cert_and_key_pairs->head = NULL;
    config->cert_and_key_pairs->private_key.rsa = NULL;
    config->cert_and_key_pairs->ocsp_status.data = NULL;
    config->cert_and_key_pairs->ocsp_status.size = 0;
    config->cert_and_key_pairs->sct_list.data = NULL;
    config->cert_and_key_pairs->sct_list.size = 0;

    /* Put the private key pem in a stuffer */
    GUARD(s2n_stuffer_alloc_ro_from_string(&key_in_stuffer, private_key_pem));
    GUARD(s2n_stuffer_growable_alloc(&key_out_stuffer, strlen(private_key_pem)));

    /* Convert pem to asn1 and asn1 to the private key. Handles both PKCS#1 and PKCS#8 formats */
    GUARD(s2n_stuffer_rsa_private_key_from_pem(&key_in_stuffer, &key_out_stuffer));
    GUARD(s2n_stuffer_free(&key_in_stuffer));
    key_blob.size = s2n_stuffer_data_available(&key_out_stuffer);
    key_blob.data = s2n_stuffer_raw_read(&key_out_stuffer, key_blob.size);
    notnull_check(key_blob.data);
    GUARD(s2n_asn1der_to_rsa_private_key(&config->cert_and_key_pairs->private_key, &key_blob));
    GUARD(s2n_stuffer_free(&key_out_stuffer));

    /* Turn the chain into a stuffer */
    GUARD(s2n_stuffer_alloc_ro_from_string(&chain_in_stuffer, cert_chain_pem));
    GUARD(s2n_stuffer_growable_alloc(&cert_out_stuffer, 2048));

    struct s2n_cert_chain **insert = &config->cert_and_key_pairs->head;
    uint32_t chain_size = 0;
    do {
        struct s2n_cert_chain *new_node;

        if (s2n_stuffer_certificate_from_pem(&chain_in_stuffer, &cert_out_stuffer) < 0) {
            if (chain_size == 0) {
                S2N_ERROR(S2N_ERR_NO_CERTIFICATE_IN_PEM);
            }
            break;
        }

        GUARD(s2n_alloc(&mem, sizeof(struct s2n_cert_chain)));
        new_node = (struct s2n_cert_chain *)(void *)mem.data;

        GUARD(s2n_alloc(&new_node->cert, s2n_stuffer_data_available(&cert_out_stuffer)));
        GUARD(s2n_stuffer_read(&cert_out_stuffer, &new_node->cert));

        /* Additional 3 bytes for the length field in the protocol */
        chain_size += new_node->cert.size + 3;
        new_node->next = NULL;
        *insert = new_node;
        insert = &new_node->next;
    } while (s2n_stuffer_data_available(&chain_in_stuffer));

    const uint32_t leftover_chain_amount = s2n_stuffer_data_available(&chain_in_stuffer);
    GUARD(s2n_stuffer_free(&chain_in_stuffer));
    GUARD(s2n_stuffer_free(&cert_out_stuffer));

    /* Leftover data at this point means one of two things:
     * A bug in s2n's PEM parsing OR a malformed PEM in the user's chain.
     * Be conservative and fail instead of using a partial chain.
     */
    if (leftover_chain_amount > 0) {
        S2N_ERROR(S2N_ERR_INVALID_PEM);
    }

    config->cert_and_key_pairs->chain_size = chain_size;

    /* Validate the leaf cert's public key matches the provided private key */
    struct s2n_rsa_public_key public_key;
    GUARD(s2n_asn1der_to_rsa_public_key(&public_key, &config->cert_and_key_pairs->head->cert));
    const int key_match_ret = s2n_rsa_keys_match(&public_key, &config->cert_and_key_pairs->private_key);
    GUARD(s2n_rsa_public_key_free(&public_key));
    if (key_match_ret < 0) {
        /* s2n_errno already set */
        return -1;
    }

    return 0;
}

int s2n_config_add_dhparams(struct s2n_config *config, const char *dhparams_pem)
{
    struct s2n_stuffer dhparams_in_stuffer, dhparams_out_stuffer;
    struct s2n_blob dhparams_blob;
    struct s2n_blob mem;

    /* Allocate the memory for the chain and key struct */
    GUARD(s2n_alloc(&mem, sizeof(struct s2n_dh_params)));
    config->dhparams = (struct s2n_dh_params *)(void *)mem.data;

    GUARD(s2n_stuffer_alloc_ro_from_string(&dhparams_in_stuffer, dhparams_pem));
    GUARD(s2n_stuffer_growable_alloc(&dhparams_out_stuffer, strlen(dhparams_pem)));

    /* Convert pem to asn1 and asn1 to the private key */
    GUARD(s2n_stuffer_dhparams_from_pem(&dhparams_in_stuffer, &dhparams_out_stuffer));

    GUARD(s2n_stuffer_free(&dhparams_in_stuffer));

    dhparams_blob.size = s2n_stuffer_data_available(&dhparams_out_stuffer);
    dhparams_blob.data = s2n_stuffer_raw_read(&dhparams_out_stuffer, dhparams_blob.size);
    notnull_check(dhparams_blob.data);

    GUARD(s2n_pkcs3_to_dh_params(config->dhparams, &dhparams_blob));

    GUARD(s2n_free(&dhparams_blob));

    return 0;
}

int s2n_config_set_nanoseconds_since_epoch_callback(struct s2n_config *config, int (*nanoseconds_since_epoch) (void *, uint64_t *), void *data)
{
    notnull_check(nanoseconds_since_epoch);

    config->nanoseconds_since_epoch = nanoseconds_since_epoch;
    config->data_for_nanoseconds_since_epoch = data;

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

    if (mfl_code > S2N_TLS_MAX_FRAG_LEN_4096) {
        S2N_ERROR(S2N_ERR_INVALID_MAX_FRAG_LEN);
    }

    config->mfl_code = mfl_code;

    return 0;
}

int s2n_config_accept_max_fragment_length(struct s2n_config *config)
{
    notnull_check(config);

    config->accept_mfl = 1;

    return 0;
}

