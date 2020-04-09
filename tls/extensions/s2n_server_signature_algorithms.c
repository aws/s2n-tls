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
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_signature_algorithms.h"

#include "utils/s2n_safety.h"

int s2n_extensions_server_signature_algorithms_size(struct s2n_connection *conn)
{
    /* extra 6 = 2 from extension type, 2 from extension size, 2 from list length */
    return s2n_supported_sig_scheme_list_size(conn) + 6;
}

int s2n_extensions_server_signature_algorithms_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    /* The extension header */
    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SIGNATURE_ALGORITHMS));

    const uint16_t total_size = s2n_extensions_server_signature_algorithms_size(conn);
    /* Subtract 4 to account for the extension type (2) and extension size (2) fields */
    const uint16_t extension_size = total_size - 4;

    GUARD(s2n_stuffer_write_uint16(out, extension_size));
    GUARD(s2n_send_supported_sig_scheme_list(conn, out));

    return 0;
}

int s2n_extensions_server_signature_algorithms_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    return s2n_recv_supported_sig_scheme_list(extension, &conn->handshake_params.server_sig_hash_algs);
}
