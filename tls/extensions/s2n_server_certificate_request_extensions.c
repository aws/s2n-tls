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

#include "error/s2n_errno.h"
#include "s2n_server_signature_algorithms.h"
#include "utils/s2n_safety.h"
#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"

int s2n_server_certificate_request_extensions_recv(struct s2n_connection *conn, struct s2n_blob *extensions)
{
    uint8_t processed_sig_algs = 0;
    struct s2n_stuffer ext_stuffer = {0};
    GUARD(s2n_stuffer_init(&ext_stuffer, extensions));
    GUARD(s2n_stuffer_write(&ext_stuffer, extensions));

    while (s2n_stuffer_data_available(&ext_stuffer)) {
        struct s2n_blob ext = {0};
        uint16_t extension_type, extension_size;
        struct s2n_stuffer current_extension = {0};

        /* check there is at least length 4 available to read the following two uint16 values */
        S2N_ERROR_IF(s2n_stuffer_data_available(&ext_stuffer) < 4, S2N_ERR_BAD_MESSAGE);
        GUARD(s2n_stuffer_read_uint16(&ext_stuffer, &extension_type));
        GUARD(s2n_stuffer_read_uint16(&ext_stuffer, &extension_size));
        S2N_ERROR_IF(s2n_stuffer_data_available(&ext_stuffer) < extension_size, S2N_ERR_BAD_MESSAGE);

        ext.size = extension_size;
        ext.data = s2n_stuffer_raw_read(&ext_stuffer, ext.size);
        notnull_check(ext.data);

        GUARD(s2n_stuffer_init(&current_extension, &ext));
        GUARD(s2n_stuffer_write(&current_extension, &ext));

        switch (extension_type) {
        case TLS_EXTENSION_SIGNATURE_ALGORITHMS:
            GUARD(s2n_extensions_server_signature_algorithms_recv(conn, &current_extension));
            processed_sig_algs += 1;
            break;
        case TLS_EXTENSION_SCT_LIST:
        case TLS_EXTENSION_STATUS_REQUEST:
        case TLS_EXTENSION_SERVER_NAME:
        case TLS_EXTENSION_ALPN:
        case TLS_EXTENSION_MAX_FRAG_LEN:
        case TLS_EXTENSION_RENEGOTIATION_INFO:
        case TLS_EXTENSION_SESSION_TICKET:
        case TLS_EXTENSION_SUPPORTED_VERSIONS:
        case TLS_EXTENSION_KEY_SHARE:
            S2N_ERROR(S2N_ERR_BAD_MESSAGE);
            break;
        }
    }

    /* https://tools.ietf.org/html/rfc8446#section-4.3.2
     * The "signature_algorithms" extension MUST be specified
     */
    S2N_ERROR_IF(processed_sig_algs != 1, S2N_ERR_BAD_MESSAGE);

    return 0;
}

int s2n_server_certificate_request_extensions_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
	/* For minimal implementation we only send signature algorithms */
    GUARD(s2n_extensions_server_signature_algorithms_send(conn, out));

    return 0;
}

int s2n_server_certificate_request_extensions_size(struct s2n_connection *conn)
{
	/* currently only sending signature algorithms */
	return s2n_extensions_server_signature_algorithms_size(conn);
}
