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

#include "tls/s2n_connection.h"
#include "error/s2n_errno.h"
#include "utils/s2n_safety.h"

S2N_RESULT s2n_protocol_preferences_write(struct s2n_stuffer *protocol_stuffer, const uint8_t *protocol, size_t protocol_len)
{
    ENSURE_MUT(protocol_stuffer);
    ENSURE_REF(protocol);

    /**
     *= https://tools.ietf.org/rfc/rfc7301#section-3.1
     *# Empty strings
     *# MUST NOT be included and byte strings MUST NOT be truncated.
     */
    ENSURE(protocol_len != 0, S2N_ERR_INVALID_APPLICATION_PROTOCOL);
    ENSURE(protocol_len <= 255, S2N_ERR_INVALID_APPLICATION_PROTOCOL);

    uint32_t extension_len = s2n_stuffer_data_available(protocol_stuffer) + /* len prefix */ 1 + protocol_len;
    ENSURE(extension_len <= UINT16_MAX, S2N_ERR_INVALID_APPLICATION_PROTOCOL);

    GUARD_AS_RESULT(s2n_stuffer_write_uint8(protocol_stuffer, protocol_len));
    GUARD_AS_RESULT(s2n_stuffer_write_bytes(protocol_stuffer, protocol, protocol_len));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_protocol_preferences_set(struct s2n_blob *application_protocols, const char *const *protocols, int protocol_count)
{
    ENSURE_MUT(application_protocols);

    /* NULL value indicates no preference so free the previous blob */
    if (protocols == NULL || protocol_count == 0) {
        GUARD_AS_RESULT(s2n_free(application_protocols));

        return S2N_RESULT_OK;
    }

    DEFER_CLEANUP(struct s2n_stuffer protocol_stuffer = { 0 }, s2n_stuffer_free);

    GUARD_AS_RESULT(s2n_stuffer_growable_alloc(&protocol_stuffer, 256));
    for (size_t i = 0; i < protocol_count; i++) {
        const uint8_t * protocol = (const uint8_t *)protocols[i];
        size_t length = strlen(protocols[i]);
        GUARD_RESULT(s2n_protocol_preferences_write(&protocol_stuffer, protocol, length));
    }

    GUARD_AS_RESULT(s2n_stuffer_extract_blob(&protocol_stuffer, application_protocols));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_protocol_preferences_append(struct s2n_blob *application_protocols, const uint8_t *protocol, size_t protocol_len)
{
    ENSURE_MUT(application_protocols);
    ENSURE_REF(protocol);

    struct s2n_stuffer protocol_stuffer = {0};
    GUARD_AS_RESULT(s2n_stuffer_init(&protocol_stuffer, application_protocols));
    protocol_stuffer.alloced = true;
    protocol_stuffer.growable = true;
    GUARD_AS_RESULT(s2n_stuffer_skip_write(&protocol_stuffer, application_protocols->size));

    GUARD_RESULT(s2n_protocol_preferences_write(&protocol_stuffer, protocol, protocol_len));

    // ensure the application_protocols gets updated if we reallocate
    *application_protocols = protocol_stuffer.blob;
    application_protocols->size = protocol_stuffer.write_cursor;

    return S2N_RESULT_OK;
}

int s2n_config_set_protocol_preferences(struct s2n_config *config, const char *const *protocols, int protocol_count)
{
    return S2N_RESULT_TO_POSIX(s2n_protocol_preferences_set(&config->application_protocols, protocols, protocol_count));
}

int s2n_config_append_protocol_preference(struct s2n_config *config, const uint8_t *protocol, size_t protocol_len)
{
    return S2N_RESULT_TO_POSIX(s2n_protocol_preferences_append(&config->application_protocols, protocol, protocol_len));
}

int s2n_connection_set_protocol_preferences(struct s2n_connection *conn, const char * const *protocols, int protocol_count)
{
    return S2N_RESULT_TO_POSIX(s2n_protocol_preferences_set(&conn->application_protocols_overridden, protocols, protocol_count));
}

int s2n_connection_append_protocol_preference(struct s2n_connection *conn, const uint8_t *protocol, size_t protocol_len)
{
    return S2N_RESULT_TO_POSIX(s2n_protocol_preferences_append(&conn->application_protocols_overridden, protocol, protocol_len));
}
