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

#include "s2n_extension_list.h"
#include "s2n_extension_type.h"
#include "s2n_extension_type_lists.h"

#include <s2n.h>

#include "error/s2n_errno.h"
#include "utils/s2n_safety.h"

int s2n_extension_list_send(s2n_extension_list_id list_type, struct s2n_connection *conn, struct s2n_stuffer *out)
{
    s2n_extension_type_list *extension_type_list;
    GUARD(s2n_extension_type_list_get(list_type, &extension_type_list));

    struct s2n_stuffer_reservation total_extensions_size;
    GUARD(s2n_stuffer_reserve_uint16(out, &total_extensions_size));

    for (int i = 0; i < extension_type_list->count; i++) {
        GUARD(s2n_extension_send(extension_type_list->extension_types[i], conn, out));
    }

    GUARD(s2n_stuffer_write_vector_size(total_extensions_size));
    return S2N_SUCCESS;
}

int s2n_extension_list_recv(s2n_extension_list_id list_type, struct s2n_connection *conn, struct s2n_stuffer *in)
{
    s2n_parsed_extensions_list parsed_extension_list = { 0 };
    GUARD(s2n_extension_list_parse(in, &parsed_extension_list));
    GUARD(s2n_extension_list_process(list_type, conn, &parsed_extension_list));
    return S2N_SUCCESS;
}

int s2n_extension_process(const s2n_extension_type *extension_type, struct s2n_connection *conn,
        s2n_parsed_extensions_list *parsed_extension_list)
{
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
}

int s2n_extension_list_process(s2n_extension_list_id list_type, struct s2n_connection *conn,
        s2n_parsed_extensions_list *parsed_extension_list)
{
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
}

int s2n_extension_list_parse(struct s2n_stuffer *in, s2n_parsed_extensions_list *parsed_extension_list)
{
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
}
