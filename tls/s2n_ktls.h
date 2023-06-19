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

/* ##################################
 * START kTLS specific headers
 * ##################################
 *
 * - https://elixir.bootlin.com/linux/v6.3.8/A/ident/TCP_ULP
 * - https://elixir.bootlin.com/linux/v6.3.8/A/ident/SOL_TCP
 *
 * Linux doesn't expose kTLS headers in its uapi. Its possible to get these headers
 * via glibc but support can vary depending on the version of glibc on the host.
 * Instead we define the headers inline and gate compilation to linux.
 */
#if defined(__linux__)
    /* socket definitions */
    #define S2N_TLS_ULP_NAME      "tls"
    #define S2N_TLS_ULP_NAME_SIZE sizeof(S2N_TLS_ULP_NAME)
    #define S2N_TCP_ULP           31 /* Attach a ULP to a TCP connection.  */
    #define S2N_SOL_TCP           6  /* TCP level */
#endif
/* ##################################
 * END kTLS specific headers
 * ################################## */

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
int s2n_connection_ktls_enable_tx(struct s2n_connection *conn);
int s2n_connection_ktls_enable_rx(struct s2n_connection *conn);
