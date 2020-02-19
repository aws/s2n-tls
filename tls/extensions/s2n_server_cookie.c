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

#include "tls/s2n_tls.h"

#include "tls/extensions/s2n_cookie.h"

int s2n_extensions_server_cookie_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    /* Until HelloRetryRequests are supported, the server does not support cookies */
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);

    return 0;
}

int s2n_extensions_server_cookie_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    /* Until HelloRetryRequests are supported, the server does not support cookies */
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);

    return 0;
}
