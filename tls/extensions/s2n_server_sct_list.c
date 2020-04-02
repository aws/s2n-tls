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

#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/extensions/s2n_server_sct_list.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

int s2n_server_extensions_sct_list_send_size(struct s2n_connection *conn)
{
    if (s2n_server_can_send_sct_list(conn)) {
        return 2 * sizeof(uint16_t) +
            conn->handshake_params.our_chain_and_key->sct_list.size;
    }

    return 0;
}

/* Write Signed Certificate Timestamp extension */
int s2n_server_extensions_sct_list_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    notnull_check(conn);

    if (s2n_server_can_send_sct_list(conn)) {
        struct s2n_blob *sct_list = &conn->handshake_params.our_chain_and_key->sct_list;

        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SCT_LIST));
        GUARD(s2n_stuffer_write_uint16(out, sct_list->size));
        GUARD(s2n_stuffer_write(out, sct_list));
    }

    return 0;
}

int s2n_recv_server_sct_list(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    struct s2n_blob sct_list = { .data = NULL, .size = 0 };

    sct_list.size = s2n_stuffer_data_available(extension);
    sct_list.data = s2n_stuffer_raw_read(extension, sct_list.size);
    notnull_check(sct_list.data);

    GUARD(s2n_dup(&sct_list, &conn->ct_response));

    return 0;
}
