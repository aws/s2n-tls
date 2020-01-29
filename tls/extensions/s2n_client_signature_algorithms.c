/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

int s2n_send_client_signature_algorithms_extension(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    /* The extension header */
    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SIGNATURE_ALGORITHMS));

    /* Each SignatureScheme is two bytes, and there's another two bytes for
     * the extension length field.
     */
    uint16_t num_signature_schemes = s2n_supported_sig_scheme_pref_list_len;
    uint16_t signature_schemes_size = num_signature_schemes * TLS_SIGNATURE_SCHEME_LEN;
    uint16_t extension_len_field_size = 2;

    GUARD(s2n_stuffer_write_uint16(out, extension_len_field_size + signature_schemes_size));
    GUARD(s2n_send_supported_signature_algorithms(out));

    return 0;
}

int s2n_recv_client_signature_algorithms(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    return s2n_recv_supported_sig_scheme_list(extension, &conn->handshake_params.client_sig_hash_algs);
}
