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

#include "tls/s2n_quic_support.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_tls13.h"

#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

int s2n_connection_enable_quic(struct s2n_connection *conn)
{
    /* The QUIC protocol doesn't use pre-1.3 TLS */
    ENSURE_POSIX(s2n_is_tls13_enabled(), S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

    notnull_check(conn);
    conn->quic_enabled = true;
    return S2N_SUCCESS;
}

int s2n_connection_set_quic_transport_parameters(struct s2n_connection *conn,
        const uint8_t *data_buffer, uint16_t data_len)
{
    notnull_check(conn);

    GUARD(s2n_free(&conn->our_quic_transport_parameters));
    GUARD(s2n_alloc(&conn->our_quic_transport_parameters, data_len));
    memcpy_check(conn->our_quic_transport_parameters.data, data_buffer, data_len);

    return S2N_SUCCESS;
}

int s2n_connection_get_quic_transport_parameters(struct s2n_connection *conn,
        const uint8_t **data_buffer, uint16_t *data_len)
{
    notnull_check(conn);
    notnull_check(data_buffer);
    notnull_check(data_len);

    *data_buffer = conn->peer_quic_transport_parameters.data;
    *data_len = conn->peer_quic_transport_parameters.size;

    return S2N_SUCCESS;
}
