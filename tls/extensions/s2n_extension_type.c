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
#include "tls/extensions/s2n_extension_type.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_bitmap.h"
#include "utils/s2n_safety.h"

#define TLS_EXTENSION_DATA_LENGTH_BYTES 2

/* Because there are 65536 possible extension IANAs, we will only
 * put the lowest (and most common) in a lookup table to conserve space. */
#define S2N_MAX_INDEXED_EXTENSION_IANA 60

const s2n_extension_type_id s2n_unsupported_extension = S2N_SUPPORTED_EXTENSIONS_COUNT;
s2n_extension_type_id s2n_extension_ianas_to_ids[S2N_MAX_INDEXED_EXTENSION_IANA];

int s2n_extension_type_init()
{
    /* Initialize to s2n_unsupported_extension */
    for (int i = 0; i < S2N_MAX_INDEXED_EXTENSION_IANA; i++) {
        s2n_extension_ianas_to_ids[i] = s2n_unsupported_extension;
    }

    /* Reverse the mapping */
    for (int i = 0; i < S2N_SUPPORTED_EXTENSIONS_COUNT; i++) {
        uint16_t iana_value = s2n_supported_extensions[i];
        if (iana_value < S2N_MAX_INDEXED_EXTENSION_IANA) {
            s2n_extension_ianas_to_ids[iana_value] = i;
        }
    }

    return S2N_SUCCESS;
}

/* Convert the IANA value (which ranges from 0->65535) to an id with a more
 * constrained range. That id can be used for bitfields, array indexes, etc.
 * to avoid allocating too much memory. */
s2n_extension_type_id s2n_extension_iana_value_to_id(const uint16_t iana_value)
{
    /* Check the lookup table */
    if (iana_value < S2N_MAX_INDEXED_EXTENSION_IANA) {
        return s2n_extension_ianas_to_ids[iana_value];
    }

    /* Fall back to the full list. We can handle this more
     * efficiently later if our extension list gets long. */
    for (int i = 0; i < S2N_SUPPORTED_EXTENSIONS_COUNT; i++) {
        if (s2n_supported_extensions[i] == iana_value) {
            return i;
        }
    }

    return s2n_unsupported_extension;
}

int s2n_extension_supported_iana_value_to_id(const uint16_t iana_value, s2n_extension_type_id *internal_id)
{
    notnull_check(internal_id);

    *internal_id = s2n_extension_iana_value_to_id(iana_value);
    S2N_ERROR_IF(*internal_id == s2n_unsupported_extension, S2N_ERR_UNRECOGNIZED_EXTENSION);
    return S2N_SUCCESS;
}

int s2n_extension_send(const s2n_extension_type *extension_type, struct s2n_connection *conn, struct s2n_stuffer *out)
{
    notnull_check(extension_type);
    notnull_check(extension_type->should_send);
    notnull_check(extension_type->send);
    notnull_check(conn);

    s2n_extension_type_id extension_id;
    GUARD(s2n_extension_supported_iana_value_to_id(extension_type->iana_value, &extension_id));

    /* Do not send response if request not received. */
    if (extension_type->is_response &&
            !S2N_CBIT_TEST(conn->extension_requests_received, extension_id)) {
        return S2N_SUCCESS;
    }

    /* Check if we need to send. Some extensions are only sent if specific conditions are met. */
    if (!extension_type->should_send(conn)) {
        return S2N_SUCCESS;
    }

    /* Write extension type */
    GUARD(s2n_stuffer_write_uint16(out, extension_type->iana_value));

    /* Reserve space for extension size */
    struct s2n_stuffer_reservation extension_size_bytes = {0};
    GUARD(s2n_stuffer_reserve_uint16(out, &extension_size_bytes));

    /* Write extension data */
    GUARD(extension_type->send(conn, out));

    /* Record extension size */
    GUARD(s2n_stuffer_write_vector_size(&extension_size_bytes));

    /* Set request bit flag */
    if (!extension_type->is_response) {
        S2N_CBIT_SET(conn->extension_requests_sent, extension_id);
    }

    return S2N_SUCCESS;
}

int s2n_extension_recv(const s2n_extension_type *extension_type, struct s2n_connection *conn, struct s2n_stuffer *in)
{
    notnull_check(extension_type);
    notnull_check(extension_type->recv);
    notnull_check(conn);

    s2n_extension_type_id extension_id;
    GUARD(s2n_extension_supported_iana_value_to_id(extension_type->iana_value, &extension_id));

    /* Do not accept a response if we did not send a request */
    if(extension_type->is_response &&
            !S2N_CBIT_TEST(conn->extension_requests_sent, extension_id)) {
        S2N_ERROR(S2N_ERR_UNSUPPORTED_EXTENSION);
    }

    GUARD(extension_type->recv(conn, in));

    /* Set request bit flag */
    if (!extension_type->is_response) {
        S2N_CBIT_SET(conn->extension_requests_received, extension_id);
    }

    return S2N_SUCCESS;
}

int s2n_extension_is_missing(const s2n_extension_type *extension_type, struct s2n_connection *conn)
{
    notnull_check(extension_type);
    notnull_check(extension_type->if_missing);
    notnull_check(conn);

    s2n_extension_type_id extension_id;
    GUARD(s2n_extension_supported_iana_value_to_id(extension_type->iana_value, &extension_id));

    /* Do not consider an extension missing if we did not send a request */
    if(extension_type->is_response &&
            !S2N_CBIT_TEST(conn->extension_requests_sent, extension_id)) {
        return S2N_SUCCESS;
    }

    GUARD(extension_type->if_missing(conn));

    return S2N_SUCCESS;
}

int s2n_extension_send_unimplemented(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
}

int s2n_extension_recv_unimplemented(struct s2n_connection *conn, struct s2n_stuffer *in)
{
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
}

int s2n_extension_send_noop(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    return S2N_SUCCESS;
}

int s2n_extension_recv_noop(struct s2n_connection *conn, struct s2n_stuffer *in)
{
    return S2N_SUCCESS;
}

bool s2n_extension_always_send(struct s2n_connection *conn)
{
    return true;
}

bool s2n_extension_never_send(struct s2n_connection *conn)
{
    return false;
}

bool s2n_extension_send_if_tls13_connection(struct s2n_connection *conn)
{
    return s2n_connection_get_protocol_version(conn) >= S2N_TLS13;
}

int s2n_extension_error_if_missing(struct s2n_connection *conn)
{
    S2N_ERROR(S2N_ERR_MISSING_EXTENSION);
}

int s2n_extension_noop_if_missing(struct s2n_connection *conn)
{
    return S2N_SUCCESS;
}
