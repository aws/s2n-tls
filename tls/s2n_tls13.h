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
#include "tls/s2n_crypto.h"
#include "utils/s2n_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

#if S2N_GCC_VERSION_AT_LEAST(4, 5, 0)
    S2N_API
    __attribute__((deprecated("The use of TLS1.3 is configured through security policies")))
    extern int s2n_enable_tls13();
#else
    S2N_API
    __attribute__((deprecated))
    extern int s2n_enable_tls13();
#endif

#ifdef __cplusplus
}
#endif


/* from RFC: https://tools.ietf.org/html/rfc8446#section-4.1.3*/
extern uint8_t hello_retry_req_random[S2N_TLS_RANDOM_DATA_LEN];

bool s2n_use_default_tls13_config();
int s2n_disable_tls13();
int s2n_reset_tls13();
bool s2n_is_valid_tls13_cipher(const uint8_t version[2]);

bool s2n_is_middlebox_compat_enabled(struct s2n_connection *conn);

bool s2n_is_hello_retry_handshake(struct s2n_connection *conn);
bool s2n_is_hello_retry_message(struct s2n_connection *conn);
int s2n_set_hello_retry_required(struct s2n_connection *conn);
