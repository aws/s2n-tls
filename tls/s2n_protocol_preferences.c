/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

int s2n_blob_set_protocol_preferences(struct s2n_blob *application_protocols, const char *const *protocols, int protocol_count)
{
    struct s2n_stuffer protocol_stuffer = {0};

    GUARD(s2n_free(application_protocols));

    if (protocols == NULL || protocol_count == 0) {
        /* NULL value indicates no preference, so nothing to do */
        return 0;
    }

    GUARD(s2n_stuffer_growable_alloc(&protocol_stuffer, 256));
    for (int i = 0; i < protocol_count; i++) {
        size_t length = strlen(protocols[i]);
        uint8_t protocol[255];

        S2N_ERROR_IF(length > 255 || (s2n_stuffer_data_available(&protocol_stuffer) + length + 1) > 65535, S2N_ERR_APPLICATION_PROTOCOL_TOO_LONG);
        memcpy_check(protocol, protocols[i], length);
        GUARD(s2n_stuffer_write_uint8(&protocol_stuffer, length));
        GUARD(s2n_stuffer_write_bytes(&protocol_stuffer, protocol, length));
    }

    GUARD(s2n_stuffer_extract_blob(&protocol_stuffer, application_protocols));
    GUARD(s2n_stuffer_free(&protocol_stuffer));
    return 0;
}

int s2n_config_set_protocol_preferences(struct s2n_config *config, const char *const *protocols, int protocol_count)
{
    return s2n_blob_set_protocol_preferences(&config->application_protocols, protocols, protocol_count);
}

int s2n_connection_set_protocol_preferences(struct s2n_connection *conn, const char * const *protocols, int protocol_count)
{
    return s2n_blob_set_protocol_preferences(&conn->application_protocols_overridden, protocols, protocol_count);
}
