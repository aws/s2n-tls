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

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_dhe.h"

#include "utils/s2n_blob.h"
#include "api/s2n.h"

struct s2n_cipher_preferences;

struct s2n_config {
    struct s2n_dh_params *dhparams;
    struct s2n_cert_chain_and_key *cert_and_key_pairs;
    const struct s2n_cipher_preferences *cipher_preferences;
    struct s2n_blob application_protocols;
    s2n_status_request_type status_request_type;
    int (*nanoseconds_since_epoch) (void *, uint64_t *);
    void *data_for_nanoseconds_since_epoch;

    s2n_client_hello_fn *client_hello_cb;
    void *client_hello_cb_ctx;

    /* If caching is being used, these must all be set */
    int (*cache_store) (void *data, uint64_t ttl_in_seconds, const void *key, uint64_t key_size, const void *value, uint64_t value_size);
    void *cache_store_data;

    int (*cache_retrieve) (void *data, const void *key, uint64_t key_size, void *value, uint64_t * value_size);
    void *cache_retrieve_data;

    int (*cache_delete) (void *data, const void *key, uint64_t key_size);
    void *cache_delete_data;
    s2n_ct_support_level ct_type;

    s2n_cert_auth_type client_cert_auth_type;
    verify_cert_trust_chain *verify_cert_chain_cb;
    void *verify_cert_context;
};

extern struct s2n_config s2n_default_config;
extern struct s2n_config s2n_default_fips_config;
