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

#include "tls/s2n_crypto.h"

/* from RFC: https://tools.ietf.org/html/rfc8446#section-4.1.3*/
extern uint8_t hello_retry_req_random[S2N_TLS_RANDOM_DATA_LEN];

int s2n_is_tls13_supported();
int s2n_is_tls13_enabled();
int s2n_enable_tls13();
int s2n_disable_tls13();
bool s2n_is_valid_tls13_cipher(const uint8_t version[2]);

bool s2n_is_hello_retry_handshake(struct s2n_connection *conn);
bool s2n_is_hello_retry_message(struct s2n_connection *conn);
int s2n_set_hello_retry_required(struct s2n_connection *conn);
int s2n_hello_retry_validate(struct s2n_connection *conn);
