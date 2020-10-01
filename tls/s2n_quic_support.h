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

#include "api/s2n.h"

/*
 * APIs intended to support an external implementation of the QUIC protocol:
 * https://datatracker.ietf.org/wg/quic/about/
 *
 * QUIC requires access to parts of S2N not usually surfaced to customers. These APIs change
 * the behavior of S2N in potentially dangerous ways and should only be used by implementations
 * of the QUIC protocol.
 *
 * Additionally, the QUIC RFC is not yet finalized, so all QUIC APIs are considered experimental
 * and are subject to change without notice. They should only be used for testing purposes.
 */

S2N_API int s2n_connection_enable_quic(struct s2n_connection *conn);

/*
 * Set the data to be sent in the quic_transport_parameters extension.
 * The data provided will be copied into a buffer owned by S2N.
 */
S2N_API int s2n_connection_set_quic_transport_parameters(struct s2n_connection *conn,
        const uint8_t *data_buffer, uint16_t data_len);

/*
 * Retrieve the data from the peer's quic_transport_parameters extension.
 * data_buffer will be set to a buffer owned by S2N which will be freed when the connection is freed.
 * data_len will be set to the length of the data returned.
 *
 * S2N treats the extension data as opaque bytes and performs no validation.
 */
S2N_API int s2n_connection_get_quic_transport_parameters(struct s2n_connection *conn,
        const uint8_t **data_buffer, uint16_t *data_len);
