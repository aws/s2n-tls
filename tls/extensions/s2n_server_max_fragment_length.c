/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_connection.h"

#include "tls/extensions/s2n_server_max_fragment_length.h"

int s2n_recv_server_max_fragment_length(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint8_t mfl_code;
    GUARD(s2n_stuffer_read_uint8(extension, &mfl_code));
    S2N_ERROR_IF(mfl_code != conn->config->mfl_code, S2N_ERR_MAX_FRAG_LEN_MISMATCH);

    return 0;
}
