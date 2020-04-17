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

#include <s2n.h>

#include "error/s2n_errno.h"
#include "tls/extensions/s2n_extension_type.h"
#include "tls/s2n_client_extensions.h"
#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_safety.h"

#define TLS_EXTENSION_DATA_LENGTH_BYTES 2

/* Because there are 65536 possible extension IANAs, we will only
 * put the lowest (and most common) in a lookup table to conserve space. */
#define S2N_MAX_INDEXED_EXTENSION_IANA 60

const uint16_t s2n_supported_extensions[] = {
    TLS_EXTENSION_RENEGOTIATION_INFO,
    TLS_EXTENSION_PQ_KEM_PARAMETERS,
    TLS_EXTENSION_SERVER_NAME,
    TLS_EXTENSION_MAX_FRAG_LEN,
    TLS_EXTENSION_STATUS_REQUEST,
    TLS_EXTENSION_SUPPORTED_GROUPS,
    TLS_EXTENSION_EC_POINT_FORMATS,
    TLS_EXTENSION_SIGNATURE_ALGORITHMS,
    TLS_EXTENSION_ALPN,
    TLS_EXTENSION_SCT_LIST,
    TLS_EXTENSION_SESSION_TICKET,
    TLS_EXTENSION_SUPPORTED_VERSIONS,
    TLS_EXTENSION_KEY_SHARE,
};
const s2n_extension_type_id s2n_supported_extensions_count = sizeof(s2n_supported_extensions) / sizeof(uint16_t);
const s2n_extension_type_id s2n_unsupported_extension = sizeof(s2n_supported_extensions) / sizeof(uint16_t);

s2n_extension_type_id s2n_extension_ianas_to_ids[S2N_MAX_INDEXED_EXTENSION_IANA];

int s2n_extension_type_init()
{
    /* Initialize to s2n_unsupported_extension */
    for (int i = 0; i < S2N_MAX_INDEXED_EXTENSION_IANA; i++) {
        s2n_extension_ianas_to_ids[i] = s2n_unsupported_extension;
    }

    /* Reverse the mapping */
    for (int i = 0; i < s2n_supported_extensions_count; i++) {
        uint16_t iana_value = s2n_supported_extensions[i];
        if (iana_value < S2N_MAX_INDEXED_EXTENSION_IANA) {
            s2n_extension_ianas_to_ids[iana_value] = i;
        }

        /* This is needed to support the ClientHello's current method
         * of skipping unknown extensions when parsing. */
        s2n_register_extension(iana_value);
    }

    return S2N_SUCCESS;
}

s2n_extension_type_id s2n_extension_iana_value_to_id(uint16_t iana_value)
{
    /* Check the lookup table */
    if (iana_value < S2N_MAX_INDEXED_EXTENSION_IANA) {
        return s2n_extension_ianas_to_ids[iana_value];
    }

    /* Fall back to the full list. We can handle this more
     * efficiently later if our extension list gets long. */
    for (int i = 0; i < s2n_supported_extensions_count; i++) {
        if (s2n_supported_extensions[i] == iana_value) {
            return i;
        }
    }

    return s2n_unsupported_extension;
}

int s2n_extension_send(s2n_extension_type *extension_type, struct s2n_connection *conn, struct s2n_stuffer *out)
{
    notnull_check(extension_type);
    notnull_check(conn);
    notnull_check(out);

    GUARD(s2n_stuffer_write_uint16(out, extension_type->iana_value));

    struct s2n_stuffer size_stuffer = *out;
    GUARD(s2n_stuffer_skip_write(out, TLS_EXTENSION_DATA_LENGTH_BYTES));

    int result = extension_type->send(conn, out);

    GUARD(s2n_stuffer_write_uint16(&size_stuffer,
            s2n_stuffer_data_available(out) - s2n_stuffer_data_available(&size_stuffer) - TLS_EXTENSION_DATA_LENGTH_BYTES));

    return result;
}

int s2n_extension_recv(s2n_extension_type *extension_type, struct s2n_connection *conn, struct s2n_stuffer *in)
{
    notnull_check(extension_type);
    notnull_check(conn);
    notnull_check(in);

    return extension_type->recv(conn, in);
}

int s2n_extension_send_unimplemented(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
}

int s2n_extension_recv_unimplemented(struct s2n_connection *conn, struct s2n_stuffer *in)
{
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
}

int s2n_extension_always_send(struct s2n_connection *conn)
{
    return S2N_SUCCESS;
}

int s2n_extension_never_send(struct s2n_connection *conn)
{
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
}

int s2n_extension_always_recv(struct s2n_connection *conn, uint8_t *is_required)
{
    *is_required = 1;
    return S2N_SUCCESS;
}

int s2n_extension_may_recv(struct s2n_connection *conn, uint8_t *is_required)
{
    *is_required = 0;
    return S2N_SUCCESS;
}
