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

#include "crypto/s2n_tls13_keys.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"
#include "tls/s2n_connection.h"

int s2n_tls13_mac_verify(struct s2n_tls13_keys *keys, struct s2n_blob *finished_verify, struct s2n_blob *wire_verify);

#define s2n_get_hash_state(hash_state, alg, conn) \
    struct s2n_hash_state hash_state = {0}; \
    GUARD(s2n_handshake_get_hash_state(conn, alg, &hash_state));

/* Creates a reference to tls13_keys from connection */
#define s2n_tls13_connection_keys(keys, conn) \
    DEFER_CLEANUP(struct s2n_tls13_keys keys = {0}, s2n_tls13_keys_free);\
    GUARD(s2n_tls13_keys_from_conn(&keys, conn));

int s2n_tls13_keys_from_conn(struct s2n_tls13_keys *keys, struct s2n_connection *conn);

int s2n_tls13_handle_handshake_secrets(struct s2n_connection *conn);
int s2n_tls13_handle_application_secrets(struct s2n_connection *conn);

