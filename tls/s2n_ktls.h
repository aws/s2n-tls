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

#include <stdbool.h>

#include "utils/s2n_result.h"

struct s2n_config;
struct s2n_connection;

/* --- unstable API ---
 *
 * These will eventually be moved to unstable/ktls.h once kTLS is implemented
 */

typedef enum {
    /** Enable kTLS for both rx and tx socket. */
    S2N_KTLS_MODE_DISABLED = 0,
    /** Enable kTLS for the tx socket. */
    S2N_KTLS_MODE_TX = 1 << 0,
    /** Enable kTLS for the rx socket. */
    S2N_KTLS_MODE_RX = 1 << 1,
    /** Enable kTLS for both rx and tx socket. */
    S2N_KTLS_MODE_DUPLEX = S2N_KTLS_MODE_RX | S2N_KTLS_MODE_TX,
} s2n_ktls_mode;

int s2n_config_ktls_enable(struct s2n_config *config, s2n_ktls_mode mode);

bool s2n_connection_is_ktls_enabled(struct s2n_connection *conn, s2n_ktls_mode mode);

/* --- unstable API --- */

bool s2n_ktls_is_ktls_mode_eq(s2n_ktls_mode a, s2n_ktls_mode b);
S2N_RESULT s2n_ktls_enable(struct s2n_connection *conn, s2n_ktls_mode ktls_mode);
S2N_RESULT s2n_ktls_validate(struct s2n_connection *conn, s2n_ktls_mode ktls_mode);
