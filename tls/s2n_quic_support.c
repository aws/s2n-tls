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
#include "utils/s2n_safety.h"

int s2n_connection_enable_quic(struct s2n_connection *conn)
{
    /* The QUIC RFC is not yet finalized, so all QUIC APIs are
     * considered experimental and subject to change.
     * They should only be used for testing purposes.
     */
    ENSURE_POSIX(S2N_IN_TEST, S2N_ERR_NOT_IN_TEST);

    /* The QUIC protocol doesn't use pre-1.3 TLS */
    ENSURE_POSIX(s2n_is_tls13_enabled(), S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

    notnull_check(conn);
    conn->quic_enabled = true;
    return S2N_SUCCESS;
}
