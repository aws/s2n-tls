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

#include "api/s2n.h"

#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"

int s2n_client_hello_request_recv(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE(conn->actual_protocol_version < S2N_TLS13, S2N_ERR_BAD_MESSAGE);

    /*
     *= https://tools.ietf.org/rfc/rfc5246#section-7.4.1.1
     *# The HelloRequest message MAY be sent by the server at any time.
     */
    POSIX_ENSURE(conn->mode == S2N_CLIENT, S2N_ERR_BAD_MESSAGE);

    /*
     *= https://tools.ietf.org/rfc/rfc5246#section-7.4.1.1
     *# This message will be ignored by the client if the client is
     *# currently negotiating a session.  This message MAY be ignored by
     *# the client if it does not wish to renegotiate a session, or the
     *# client may, if it wishes, respond with a no_renegotiation alert.
     */
    return S2N_SUCCESS;
}
