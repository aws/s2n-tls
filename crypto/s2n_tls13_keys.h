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

#include <stdint.h>

#include "utils/s2n_blob.h"

#define S2N_TLS13_SECRET_MAX_LEN SHA384_DIGEST_LENGTH

struct s2n_tls13_keys {
    s2n_hmac_algorithm hmac_algorithm;
    s2n_hash_algorithm hash_algorithm;

    uint8_t size;

    struct s2n_blob current_secret;
    struct s2n_blob derive_secret;
    uint8_t current_secret_bytes[S2N_TLS13_SECRET_MAX_LEN];
    uint8_t derive_secret_bytes[S2N_TLS13_SECRET_MAX_LEN];

    struct s2n_hmac_state hmac;
};

/* Defines TLS 1.3 HKDF Labels */
extern const struct s2n_blob s2n_tls13_label_derived_secret;
extern const struct s2n_blob s2n_tls13_label_external_psk_binder_key;
extern const struct s2n_blob s2n_tls13_label_resumption_psk_binder_key;

extern const struct s2n_blob s2n_tls13_label_client_early_traffic_secret;
extern const struct s2n_blob s2n_tls13_label_early_exporter_master_secret;

extern const struct s2n_blob s2n_tls13_label_client_handshake_traffic_secret;
extern const struct s2n_blob s2n_tls13_label_server_handshake_traffic_secret;

extern const struct s2n_blob s2n_tls13_label_client_application_traffic_secret;
extern const struct s2n_blob s2n_tls13_label_server_application_traffic_secret;

extern const struct s2n_blob s2n_tls13_label_exporter_master_secret;
extern const struct s2n_blob s2n_tls13_label_resumption_master_secret;

/* Traffic secret labels */

extern const struct s2n_blob s2n_tls13_label_traffic_secret_key;
extern const struct s2n_blob s2n_tls13_label_traffic_secret_iv;

#define s2n_tls13_key_blob(name, bytes) \
    s2n_stack_blob(name, bytes, S2N_TLS13_SECRET_MAX_LEN)

int s2n_tls13_keys_init(struct s2n_tls13_keys *handshake, s2n_hmac_algorithm alg);
int s2n_tls13_derive_early_secrets(struct s2n_tls13_keys *handshake);
int s2n_tls13_derive_handshake_secrets(struct s2n_tls13_keys *handshake,
                                        const struct s2n_blob *ecdhe,
                                        struct s2n_hash_state *client_server_hello_hash,
                                        struct s2n_blob *client_secret,
                                        struct s2n_blob *server_secret);
int s2n_tls13_derive_application_secrets(struct s2n_tls13_keys *handshake, struct s2n_hash_state *hashes, struct s2n_blob *client_secret, struct s2n_blob *server_secret);

int s2n_tls13_derive_traffic_keys(struct s2n_tls13_keys *handshake, struct s2n_blob *secret, struct s2n_blob *key, struct s2n_blob *iv);
