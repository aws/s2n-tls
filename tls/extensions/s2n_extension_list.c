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

#define s2n_parsed_extension_is_empty(parsed_extension) (parsed_extension->extension.data == NULL)

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

static int s2n_extension_parse(struct s2n_stuffer *in, s2n_parsed_extension *parsed_extensions)
{
    notnull_check(parsed_extensions);

    uint16_t extension_type;
    ENSURE_POSIX(s2n_stuffer_read_uint16(in, &extension_type) == S2N_SUCCESS,
            S2N_ERR_BAD_MESSAGE);

    uint16_t extension_size;
    ENSURE_POSIX(s2n_stuffer_read_uint16(in, &extension_size) == S2N_SUCCESS,
            S2N_ERR_BAD_MESSAGE);

    uint8_t *extension_data = s2n_stuffer_raw_read(in, extension_size);
    ENSURE_POSIX(extension_data != NULL, S2N_ERR_BAD_MESSAGE);

    s2n_extension_type_id extension_id;
    if (s2n_extension_supported_iana_value_to_id(extension_type, &extension_id) != S2N_SUCCESS) {
        /* Ignore unknown extensions */
        return S2N_SUCCESS;
    }

    s2n_parsed_extension *parsed_extension = &parsed_extensions[extension_id];

    /* Error if extension is a duplicate */
    ENSURE_POSIX(s2n_parsed_extension_is_empty(parsed_extension),
            S2N_ERR_DUPLICATE_EXTENSION);

    /* Fill in parsed extension */
    parsed_extension->extension_type = extension_type;
    GUARD(s2n_blob_init(&parsed_extension->extension, extension_data, extension_size));

    return S2N_SUCCESS;
}

int s2n_extension_list_parse(struct s2n_stuffer *in, s2n_parsed_extensions_list *parsed_extension_list)
{
    notnull_check(in);
    notnull_check(parsed_extension_list);

    memset_check((s2n_parsed_extension*) parsed_extension_list->parsed_extensions, 0, S2N_PARSED_EXTENSIONS_COUNT);

    uint16_t total_extensions_size;
    if (s2n_stuffer_read_uint16(in, &total_extensions_size) != S2N_SUCCESS) {
        total_extensions_size = 0;
    }

    uint8_t *extensions_data = s2n_stuffer_raw_read(in, total_extensions_size);
    ENSURE_POSIX(extensions_data != NULL, S2N_ERR_BAD_MESSAGE);

    GUARD(s2n_blob_init(&parsed_extension_list->raw, extensions_data, total_extensions_size));

    struct s2n_stuffer extensions_stuffer;
    GUARD(s2n_stuffer_init(&extensions_stuffer, &parsed_extension_list->raw));
    GUARD(s2n_stuffer_skip_write(&extensions_stuffer, total_extensions_size));

    while (s2n_stuffer_data_available(&extensions_stuffer)) {
        GUARD(s2n_extension_parse(&extensions_stuffer, parsed_extension_list->parsed_extensions));
    }

    return S2N_SUCCESS;
}
