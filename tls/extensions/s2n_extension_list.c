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

#define s2n_parsed_extension_is_valid(parsed_extension) ((parsed_extension)->extension.data != NULL)

static const s2n_parsed_extension empty_parsed_extensions[S2N_PARSED_EXTENSIONS_COUNT] = { 0 };

int s2n_extension_list_send(s2n_extension_list_id list_type, struct s2n_connection *conn, struct s2n_stuffer *out)
{
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
}

int s2n_extension_list_recv(s2n_extension_list_id list_type, struct s2n_connection *conn, struct s2n_stuffer *in)
{
    s2n_parsed_extensions_list parsed_extension_list = { 0 };
    GUARD(s2n_extension_list_parse(in, &parsed_extension_list));
    GUARD(s2n_extension_list_process(list_type, conn, &parsed_extension_list));
    return S2N_SUCCESS;
}

static int s2n_extension_process_impl(const s2n_extension_type *extension_type, s2n_extension_type_id extension_id,
        struct s2n_connection *conn, s2n_parsed_extension *parsed_extensions)
{
    notnull_check(extension_type);
    notnull_check(parsed_extensions);

    if (!s2n_parsed_extension_is_valid(&parsed_extensions[extension_id])) {
        GUARD(s2n_extension_is_missing(extension_type, conn));
        return S2N_SUCCESS;
    }

    ENSURE_POSIX(parsed_extensions[extension_id].extension_type == extension_type->iana_value,
            S2N_ERR_INVALID_PARSED_EXTENSIONS);

    struct s2n_stuffer extension_stuffer;
    GUARD(s2n_stuffer_init(&extension_stuffer, &parsed_extensions[extension_id].extension));
    GUARD(s2n_stuffer_skip_write(&extension_stuffer, parsed_extensions[extension_id].extension.size));

    GUARD(s2n_extension_recv(extension_type, conn, &extension_stuffer));

    return S2N_SUCCESS;
}

int s2n_extension_process(const s2n_extension_type *extension_type, struct s2n_connection *conn,
        s2n_parsed_extensions_list *parsed_extension_list)
{
    notnull_check(parsed_extension_list);
    notnull_check(extension_type);

    s2n_extension_type_id extension_id;
    GUARD(s2n_extension_supported_iana_value_to_id(extension_type->iana_value, &extension_id));

    int result = s2n_extension_process_impl(extension_type, extension_id, conn, parsed_extension_list->parsed_extensions);

    /* Wipe parsed_extension.
     * We can check for unprocessed extensions later by checking for non-blank parsed_extensions. */
    parsed_extension_list->parsed_extensions[extension_id] = empty_parsed_extensions[0];

    return result;
}

int s2n_extension_list_process(s2n_extension_list_id list_type, struct s2n_connection *conn,
        s2n_parsed_extensions_list *parsed_extension_list)
{
    notnull_check(parsed_extension_list);

    s2n_extension_type_list *extension_type_list;
    GUARD(s2n_extension_type_list_get(list_type, &extension_type_list));

    for (int i = 0; i < extension_type_list->count; i++) {
        GUARD(s2n_extension_process(extension_type_list->extension_types[i],
                conn, parsed_extension_list));
    }

    /* If we did not process an extension, than that extension is not allowed on this message type. */
    ENSURE_POSIX(memcmp(parsed_extension_list->parsed_extensions, empty_parsed_extensions, sizeof(empty_parsed_extensions)) == 0,
            S2N_ERR_UNSUPPORTED_EXTENSION);

    return S2N_SUCCESS;
}

int s2n_extension_list_parse(struct s2n_stuffer *in, s2n_parsed_extensions_list *parsed_extension_list)
{
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
}
