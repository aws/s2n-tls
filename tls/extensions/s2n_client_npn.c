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

#include <sys/param.h>
#include <stdint.h>

#include "tls/extensions/s2n_npn.h"
#include "tls/extensions/s2n_client_alpn.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"

#include "utils/s2n_safety.h"

bool s2n_npn_should_send(struct s2n_connection *conn)
{
    return conn && conn->config && conn->config->npn_supported && s2n_client_alpn_should_send(conn);
}

const s2n_extension_type s2n_client_npn_extension = {
    .iana_value = TLS_EXTENSION_NPN,
    .is_response = false,
    .send = s2n_extension_send_noop,
    .recv = s2n_extension_recv_noop,
    .should_send = s2n_npn_should_send,
    .if_missing = s2n_extension_noop_if_missing,
};
