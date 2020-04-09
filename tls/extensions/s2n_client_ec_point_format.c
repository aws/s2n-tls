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

#include "tls/extensions/s2n_client_ec_point_format.h"
#include "tls/s2n_tls.h"

#include "utils/s2n_safety.h"

int s2n_recv_client_ec_point_formats(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    /**
     * Only uncompressed points are supported by the server and the client must include it in
     * the extension. Just skip the extension.
     */
    conn->ec_point_formats = 1;
    return 0;
}
