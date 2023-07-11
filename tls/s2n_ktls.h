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

#include "tls/s2n_config.h"

/* Define headers needed to enable and use kTLS.
 *
 * The inline header definitions are required to compile kTLS specific code.
 * kTLS has been tested on linux. For all other platforms, kTLS is marked as
 * unsupported, and will return an unsupported error.
 */
#include "tls/s2n_ktls_parameters.h"

/* A set of kTLS configurations representing the combination of sending
 * and receiving.
 */
typedef enum {
    /* Enable kTLS for the send socket. */
    S2N_KTLS_MODE_SEND,
    /* Enable kTLS for the receive socket. */
    S2N_KTLS_MODE_RECV,
} s2n_ktls_mode;

bool s2n_ktls_is_supported_on_platform();

/* These functions will be part of the public API. */
int s2n_connection_ktls_enable_send(struct s2n_connection *conn);
int s2n_connection_ktls_enable_recv(struct s2n_connection *conn);
