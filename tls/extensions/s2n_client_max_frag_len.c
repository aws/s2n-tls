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

#include <sys/param.h>
#include <stdint.h>

#include "tls/extensions/s2n_client_max_frag_len.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"

#include "utils/s2n_safety.h"

int s2n_extensions_client_max_frag_len_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    uint16_t mfl_code_len = sizeof(conn->config->mfl_code);

    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_MAX_FRAG_LEN));
    GUARD(s2n_stuffer_write_uint16(out, mfl_code_len));
    GUARD(s2n_stuffer_write_uint8(out, conn->config->mfl_code));

    return 0;
}

int s2n_recv_client_max_frag_len(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    if (!conn->config->accept_mfl) {
        return 0;
    }

    uint8_t mfl_code;
    GUARD(s2n_stuffer_read_uint8(extension, &mfl_code));
    if (mfl_code > S2N_TLS_MAX_FRAG_LEN_4096 || mfl_code_to_length[mfl_code] > S2N_TLS_MAXIMUM_FRAGMENT_LENGTH) {
        return 0;
    }

    conn->mfl_code = mfl_code;
    conn->max_outgoing_fragment_length = mfl_code_to_length[mfl_code];
    return 0;
}
