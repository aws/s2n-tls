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

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_dhe_key_exchange.h"
#include "tls/s2n_ecdhe_key_exchange.h"
#include "tls/s2n_kem_core.h"
#include "tls/s2n_resume.h"
#include "tls/s2n_rsa_key_exchange.h"

#include "utils/s2n_safety.h"

struct s2n_kem_core s2n_rsa = {
        .flags = 0,
        .server_key_recv = &s2n_rsa_server_key_recv,
        .server_key_send = &s2n_rsa_server_key_send,
        .client_key_recv = &s2n_rsa_client_key_recv,
        .client_key_send = &s2n_rsa_client_key_send,
};

struct s2n_kem_core s2n_dhe = {
        .flags = S2N_KEY_EXCHANGE_DH | S2N_KEY_EXCHANGE_EPH,
        .server_key_recv = &s2n_dhe_server_key_recv,
        .server_key_send = &s2n_dhe_server_key_send,
        .client_key_recv = &s2n_dhe_client_key_recv,
        .client_key_send = &s2n_dhe_client_key_send,
};

struct s2n_kem_core s2n_ecdhe = {
        .flags = S2N_KEY_EXCHANGE_DH | S2N_KEY_EXCHANGE_EPH | S2N_KEY_EXCHANGE_ECC,
        .server_key_recv = &s2n_ecdhe_server_key_recv,
        .server_key_send = &s2n_ecdhe_server_key_send,
        .client_key_recv = &s2n_ecdhe_client_key_recv,
        .client_key_send = &s2n_ecdhe_client_key_send,
};
