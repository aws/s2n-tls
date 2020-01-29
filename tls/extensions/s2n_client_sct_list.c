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

#include "tls/extensions/s2n_client_sct_list.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"

#include "utils/s2n_safety.h"

int s2n_extensions_client_sct_list_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SCT_LIST));
    GUARD(s2n_stuffer_write_uint16(out, 0));

    return 0;
}

int s2n_recv_client_sct_list(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    conn->ct_level_requested = S2N_CT_SUPPORT_REQUEST;
    /* Skip reading the extension, per RFC6962 (3.1.1) it SHOULD be empty anyway  */
    return 0;
}
