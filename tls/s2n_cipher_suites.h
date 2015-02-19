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

#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_connection.h"

#include "crypto/s2n_cipher.h"
#include "crypto/s2n_hmac.h"

#include <stdint.h>

struct s2n_cipher_preferences {
    uint8_t count;
    uint8_t *wire_format;
    int minimum_protocol_version;
};

typedef enum { S2N_RSA, S2N_DH, S2N_DHE, S2N_ECDH, S2N_ECDHE, S2N_ECDHE_ECDSA } s2n_key_exchange_algorithm;

struct s2n_cipher_suite {
    const char *name;
    uint8_t value[2];
    s2n_key_exchange_algorithm key_exchange_alg;
    struct s2n_cipher *cipher;
    s2n_hmac_algorithm hmac_alg;
    uint8_t minimum_required_tls_version;
};

extern struct s2n_cipher_suite s2n_null_cipher_suite;
extern struct s2n_cipher_preferences *s2n_cipher_preferences_20140601;
extern struct s2n_cipher_preferences *s2n_cipher_preferences_20150202;
extern struct s2n_cipher_preferences *s2n_cipher_preferences_20150214;
extern struct s2n_cipher_preferences *s2n_cipher_preferences_default;

extern int s2n_set_cipher_as_client(struct s2n_connection *conn, uint8_t wire[S2N_TLS_CIPHER_SUITE_LEN]);
extern int s2n_set_cipher_as_sslv2_server(struct s2n_connection *conn, uint8_t *wire, uint16_t count);
extern int s2n_set_cipher_as_tls_server(struct s2n_connection *conn, uint8_t *wire, uint16_t count);
