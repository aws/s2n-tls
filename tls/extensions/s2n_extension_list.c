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

#define s2n_parsed_extension_is_empty(parsed_extension) ((parsed_extension)->extension.data == NULL)

static const s2n_parsed_extension empty_parsed_extensions[S2N_PARSED_EXTENSIONS_COUNT] = { 0 };

int s2n_extension_list_send(s2n_extension_list_id list_type, struct s2n_connection *conn, struct s2n_stuffer *out)
{
    s2n_extension_type_list *extension_type_list;
    POSIX_GUARD(s2n_extension_type_list_get(list_type, &extension_type_list));

    struct s2n_stuffer_reservation total_extensions_size = {0};
    POSIX_GUARD(s2n_stuffer_reserve_uint16(out, &total_extensions_size));

    for (int i = 0; i < extension_type_list->count; i++) {
        POSIX_GUARD(s2n_extension_send(extension_type_list->extension_types[i], conn, out));
    }

    POSIX_GUARD(s2n_stuffer_write_vector_size(&total_extensions_size));
    return S2N_SUCCESS;
}

int s2n_extension_list_recv(s2n_extension_list_id list_type, struct s2n_connection *conn, struct s2n_stuffer *in)
{
    s2n_parsed_extensions_list parsed_extension_list = { 0 };
    POSIX_GUARD(s2n_extension_list_parse(in, &parsed_extension_list));
    POSIX_GUARD(s2n_extension_list_process(list_type, conn, &parsed_extension_list));
    return S2N_SUCCESS;
}

static int s2n_extension_process_impl(const s2n_extension_type *extension_type, s2n_extension_type_id extension_id,
        struct s2n_connection *conn, s2n_parsed_extension *parsed_extensions)
{
    POSIX_ENSURE_REF(extension_type);
    POSIX_ENSURE_REF(parsed_extensions);

    if (s2n_parsed_extension_is_empty(&parsed_extensions[extension_id])) {
        POSIX_GUARD(s2n_extension_is_missing(extension_type, conn));
        return S2N_SUCCESS;
    }

    POSIX_ENSURE(parsed_extensions[extension_id].extension_type == extension_type->iana_value,
            S2N_ERR_INVALID_PARSED_EXTENSIONS);

    struct s2n_stuffer extension_stuffer;
    POSIX_GUARD(s2n_stuffer_init(&extension_stuffer, &parsed_extensions[extension_id].extension));
    POSIX_GUARD(s2n_stuffer_skip_write(&extension_stuffer, parsed_extensions[extension_id].extension.size));

    POSIX_GUARD(s2n_extension_recv(extension_type, conn, &extension_stuffer));

    return S2N_SUCCESS;
}

int s2n_extension_process(const s2n_extension_type *extension_type, struct s2n_connection *conn,
        s2n_parsed_extensions_list *parsed_extension_list)
{
    POSIX_ENSURE_REF(parsed_extension_list);
    POSIX_ENSURE_REF(extension_type);

    s2n_extension_type_id extension_id;
    POSIX_GUARD(s2n_extension_supported_iana_value_to_id(extension_type->iana_value, &extension_id));

    int result = s2n_extension_process_impl(extension_type, extension_id, conn, parsed_extension_list->parsed_extensions);

    /* Wipe parsed_extension.
     * We can check for unprocessed extensions later by checking for non-blank parsed_extensions. */
    parsed_extension_list->parsed_extensions[extension_id] = empty_parsed_extensions[0];

    return result;
}

int s2n_extension_list_process(s2n_extension_list_id list_type, struct s2n_connection *conn,
        s2n_parsed_extensions_list *parsed_extension_list)
{
    POSIX_ENSURE_REF(parsed_extension_list);

    s2n_extension_type_list *extension_type_list;
    POSIX_GUARD(s2n_extension_type_list_get(list_type, &extension_type_list));

    for (int i = 0; i < extension_type_list->count; i++) {
        POSIX_GUARD(s2n_extension_process(extension_type_list->extension_types[i],
                conn, parsed_extension_list));
    }

    /* If parsed_extension_list.parsed_extensions is not completely wiped at this point,
     * then we have received an extension not allowed on this message type.
     *
     * According to the RFC, we should alert and close the connection.
     * From https://tools.ietf.org/html/rfc8446#section-4.2:
     *    If an implementation receives an extension which it recognizes and which is not
     *    specified for the message in which it appears, it MUST abort the handshake with an
     *    "illegal_parameter" alert.
     *
     * However, to be more tolerant of non-compliant peers, we will just ignore and not
     * process the illegal extensions, treating them as if they are unsupported.
     */

    return S2N_SUCCESS;
}

static int s2n_extension_parse(struct s2n_stuffer *in, s2n_parsed_extension *parsed_extensions, uint16_t *wire_index)
{
    POSIX_ENSURE_REF(parsed_extensions);
    POSIX_ENSURE_REF(wire_index);

    uint16_t extension_type;
    POSIX_ENSURE(s2n_stuffer_read_uint16(in, &extension_type) == S2N_SUCCESS,
            S2N_ERR_BAD_MESSAGE);

    uint16_t extension_size;
    POSIX_ENSURE(s2n_stuffer_read_uint16(in, &extension_size) == S2N_SUCCESS,
            S2N_ERR_BAD_MESSAGE);

    uint8_t *extension_data = s2n_stuffer_raw_read(in, extension_size);
    POSIX_ENSURE(extension_data != NULL, S2N_ERR_BAD_MESSAGE);

    s2n_extension_type_id extension_id;
    if (s2n_extension_supported_iana_value_to_id(extension_type, &extension_id) != S2N_SUCCESS) {
        /* Ignore unknown extensions */
        return S2N_SUCCESS;
    }

    s2n_parsed_extension *parsed_extension = &parsed_extensions[extension_id];

    /* Error if extension is a duplicate */
    POSIX_ENSURE(s2n_parsed_extension_is_empty(parsed_extension),
            S2N_ERR_DUPLICATE_EXTENSION);

    /* Fill in parsed extension */
    parsed_extension->extension_type = extension_type;
    parsed_extension->wire_index = *wire_index;
    POSIX_GUARD(s2n_blob_init(&parsed_extension->extension, extension_data, extension_size));
    (*wire_index)++;

    return S2N_SUCCESS;
}

int s2n_extension_list_parse(struct s2n_stuffer *in, s2n_parsed_extensions_list *parsed_extension_list)
{
    POSIX_ENSURE_REF(in);
    POSIX_ENSURE_REF(parsed_extension_list);

    POSIX_CHECKED_MEMSET((s2n_parsed_extension*) parsed_extension_list->parsed_extensions,
            0, sizeof(parsed_extension_list->parsed_extensions));

    uint16_t total_extensions_size;
    if (s2n_stuffer_read_uint16(in, &total_extensions_size) != S2N_SUCCESS) {
        total_extensions_size = 0;
    }

    uint8_t *extensions_data = s2n_stuffer_raw_read(in, total_extensions_size);
    POSIX_ENSURE(extensions_data != NULL, S2N_ERR_BAD_MESSAGE);

    POSIX_GUARD(s2n_blob_init(&parsed_extension_list->raw, extensions_data, total_extensions_size));

    struct s2n_stuffer extensions_stuffer;
    POSIX_GUARD(s2n_stuffer_init(&extensions_stuffer, &parsed_extension_list->raw));
    POSIX_GUARD(s2n_stuffer_skip_write(&extensions_stuffer, total_extensions_size));

    uint16_t wire_index = 0;
    while (s2n_stuffer_data_available(&extensions_stuffer)) {
        POSIX_GUARD(s2n_extension_parse(&extensions_stuffer, parsed_extension_list->parsed_extensions, &wire_index));
    }

    parsed_extension_list->count = wire_index;
    return S2N_SUCCESS;
}
