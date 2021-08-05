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

#include "tls/s2n_connection.h"
#include "tls/s2n_prf.h"

#include "crypto/s2n_hash.h"

/* Allocationg new EVP structs is expensive, so we back them up here and reuse them */
struct s2n_connection_hmac_handles {
    struct s2n_hmac_evp_backup initial_client;
    struct s2n_hmac_evp_backup initial_client_copy;
    struct s2n_hmac_evp_backup initial_server;
    struct s2n_hmac_evp_backup secure_client;
    struct s2n_hmac_evp_backup secure_client_copy;
    struct s2n_hmac_evp_backup secure_server;
};

extern int s2n_connection_save_hmac_state(struct s2n_connection_hmac_handles *hmac_handles, struct s2n_connection *conn);
extern int s2n_connection_restore_hmac_state(struct s2n_connection *conn, struct s2n_connection_hmac_handles *hmac_handles);
