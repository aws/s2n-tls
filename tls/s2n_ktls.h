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

/* --- unstable API ---
 *
 * These will eventually be moved to unstable/ktls.h once kTLS is implemented
 */

/* A set of kTLS configurations representing the combination of sending
 * and receiving.
 *
 * s2n assumes specific binary representation for the following modes:
 *
 * S2N_KTLS_MODE_SEND | S2N_KTLS_MODE_RECV = S2N_KTLS_MODE_DUPLEX
 * 0b01               | 0b10               = 0b11
 */
typedef enum {
    /* Disable kTLS. */
    S2N_KTLS_MODE_DISABLED = 0,
    /* Enable kTLS for the send socket. */
    S2N_KTLS_MODE_SEND = 1,
    /* Enable kTLS for the recv socket. */
    S2N_KTLS_MODE_RECV = 2,
    /* Enable kTLS for both rx and tx socket. */
    S2N_KTLS_MODE_DUPLEX = 3,
} s2n_ktls_mode;

int s2n_config_ktls_enable(struct s2n_config *config, s2n_ktls_mode ktls_mode);

bool s2n_connection_matches_ktls_mode(struct s2n_connection *conn, s2n_ktls_mode ktls_mode);

/* --- unstable API --- */

S2N_RESULT s2n_ktls_enable(struct s2n_connection *conn, s2n_ktls_mode mode);
