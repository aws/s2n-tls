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

#include "tls/extensions/s2n_client_pq_kem.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_cipher_preferences.h"

#include "utils/s2n_safety.h"

int s2n_extensions_client_pq_kem_send(struct s2n_connection *conn, struct s2n_stuffer *out, uint16_t pq_kem_list_size)
{
    const struct s2n_cipher_preferences *cipher_preferences;
    GUARD(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));

    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_PQ_KEM_PARAMETERS));
    /* Overall extension length */
    GUARD(s2n_stuffer_write_uint16(out, 2 + pq_kem_list_size));
    /* Length of parameters in bytes */
    GUARD(s2n_stuffer_write_uint16(out, pq_kem_list_size));

    for (int i = 0; i < cipher_preferences->count; i++) {
        const struct s2n_iana_to_kem *supported_params = NULL;
        if(s2n_cipher_suite_to_kem(cipher_preferences->suites[i]->iana_value, &supported_params) == 0) {
            /* Each supported kem id is 2 bytes */
            for (int j = 0; j < supported_params->kem_count; j++) {
                GUARD(s2n_stuffer_write_uint16(out, supported_params->kems[j]->kem_extension_id));
            }
        }
    }

    return 0;
}

int s2n_recv_pq_kem_extension(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint16_t size_of_all;
    struct s2n_blob *proposed_kems = &conn->secure.client_pq_kem_extension;

    GUARD(s2n_stuffer_read_uint16(extension, &size_of_all));
    if (size_of_all > s2n_stuffer_data_available(extension) || size_of_all % 2) {
        /* Malformed length, ignore the extension */
        return 0;
    }

    proposed_kems->size = size_of_all;
    proposed_kems->data = s2n_stuffer_raw_read(extension, proposed_kems->size);
    notnull_check(proposed_kems->data);

    return 0;
}
