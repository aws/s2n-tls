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

#include "tls/extensions/s2n_client_signature_algorithms.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_signature_algorithms.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

static int s2n_signature_algorithms_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

const s2n_extension_type s2n_server_signature_algorithms_extension = {
    .iana_value = TLS_EXTENSION_SIGNATURE_ALGORITHMS,
    .is_response = false,
    .send = s2n_send_supported_sig_scheme_list,
    .recv = s2n_signature_algorithms_recv,
    .should_send = s2n_extension_always_send,
    .if_missing = s2n_extension_error_if_missing,
};

static int s2n_signature_algorithms_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    return s2n_recv_supported_sig_scheme_list(extension, &conn->handshake_params.server_sig_hash_algs);
}
