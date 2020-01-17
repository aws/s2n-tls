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

#include "error/s2n_errno.h"
#include "utils/s2n_safety.h"
#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_server_sct_list.h"
#include "tls/extensions/s2n_server_certificate_status.h"

static int s2n_get_number_certs_in_chain(struct s2n_cert *head, uint8_t *chain_length);

int s2n_certificate_extensions_parse(struct s2n_connection *conn, struct s2n_blob *extensions)
{
    struct s2n_stuffer extensions_in = {0};
    GUARD(s2n_stuffer_init(&extensions_in, extensions));
    GUARD(s2n_stuffer_write(&extensions_in, extensions));

    while (s2n_stuffer_data_available(&extensions_in)) {
        struct s2n_blob ext = {0};
        uint16_t extension_type, extension_size;
        struct s2n_stuffer extension = {0};

        S2N_ERROR_IF(s2n_stuffer_data_available(&extensions_in) < 4, S2N_ERR_BAD_MESSAGE);
        GUARD(s2n_stuffer_read_uint16(&extensions_in, &extension_type));
        GUARD(s2n_stuffer_read_uint16(&extensions_in, &extension_size));

        S2N_ERROR_IF(extension_size > s2n_stuffer_data_available(&extensions_in), S2N_ERR_BAD_MESSAGE);
        ext.size = extension_size;
        ext.data = s2n_stuffer_raw_read(&extensions_in, ext.size);
        notnull_check(ext.data);

        switch (extension_type) {
        case TLS_EXTENSION_SCT_LIST:
            /* only servers should be sending this extension here therefore
             * only clients should be parsing the extension
             */
            if (conn->mode == S2N_CLIENT) {
                GUARD(s2n_stuffer_init(&extension, &ext));
                GUARD(s2n_stuffer_write(&extension, &ext));
                GUARD(s2n_recv_server_sct_list(conn, &extension));
            }
            break;
        case TLS_EXTENSION_STATUS_REQUEST:
            GUARD(s2n_server_certificate_status_parse(conn, &ext));
            break;
        /* Error on known extensions that are not supposed to appear in EE
         * https://tools.ietf.org/html/rfc8446#page-37
         */
        case TLS_EXTENSION_SERVER_NAME:
        case TLS_EXTENSION_ALPN:
        case TLS_EXTENSION_MAX_FRAG_LEN:
        case TLS_EXTENSION_RENEGOTIATION_INFO:
        case TLS_EXTENSION_SESSION_TICKET:
        case TLS_EXTENSION_SUPPORTED_VERSIONS:
        case TLS_EXTENSION_KEY_SHARE:
            S2N_ERROR(S2N_ERR_BAD_MESSAGE);
            break;
        }
    }

    return 0;
}

int s2n_certificate_extensions_send(struct s2n_stuffer *out)
{
    /* For minimal TLS 1.3 implementation, we are sending no certificate extensions. 
     * We only send the length field with a value of 0. 
     */
    GUARD(s2n_stuffer_write_uint16(out, 0));
    return 0;
}

int s2n_certificate_extensions_size(struct s2n_cert *head)
{
    /* For minimal TLS 1.3 implementation, we are sending no certificate extensions. For now, size is
     * hardcoded to 2 * num_certs in order to send extensions_length field with value 0 for each cert.
     */
    uint8_t num_certs;
    GUARD(s2n_get_number_certs_in_chain(head, &num_certs));

    return 2 * num_certs;
}

int s2n_get_number_certs_in_chain(struct s2n_cert *head, uint8_t *chain_length)
{
    notnull_check(head);

    int length = 1;

    while (head->next != NULL) {
        length += 1;
        head = head->next;
    }

    *chain_length = length;
    
    return 0;
}
