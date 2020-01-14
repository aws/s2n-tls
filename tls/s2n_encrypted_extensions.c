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

#include "tls/extensions/s2n_server_alpn.h"
#include "tls/extensions/s2n_server_sct_list.h"
#include "tls/extensions/s2n_server_max_fragment_length.h"
#include "tls/extensions/s2n_server_server_name.h"

/**
  * Specified in https://tools.ietf.org/html/rfc8446#section-4.3.1
  * 
  * In all handshakes, the server MUST send the EncryptedExtensions
  * message immediately after the ServerHello message.  
  *
  * The EncryptedExtensions message contains extensions that can be
  * protected, i.e., any which are not needed to establish the
  * cryptographic context but which are not associated with individual
  * certificates. 
  **/

static int s2n_server_encrypted_extensions_parse(struct s2n_connection *conn, struct s2n_blob *extensions);

int s2n_encrypted_extensions_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    /* Calculate size of encrypted extensions. For minimal TLS 1.3, this is 0
     * as we are sending an empty EE message
     */
    uint16_t total_size = 0;

    /* Write length of extensions */
    GUARD(s2n_stuffer_write_uint16(out, total_size));

    if (total_size == 0) {
        return 0;
    }

    /* Write the extensions to the out buffer. For minimal TLS 1.3, this is
     * a noop, as we are sending an empty EE message
     */
    
    return 0;
}

int s2n_encrypted_extensions_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    uint16_t extensions_size;

    /* Read encrypted extensions size */
    S2N_ERROR_IF(2 > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);
    GUARD(s2n_stuffer_read_uint16(in, &extensions_size));
    S2N_ERROR_IF(extensions_size > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

    /* Process extensions */
    if (extensions_size > 0) {
        struct s2n_blob extensions = {0};
        extensions.size = extensions_size;
        extensions.data = s2n_stuffer_raw_read(in, extensions.size);
        notnull_check(extensions.data);

        GUARD(s2n_server_encrypted_extensions_parse(conn, &extensions));
    }

    return 0;
}

/* Note the following is a modified duplication of s2n_server_extensions_recv()
 * This will be updated with the following issue to consolidate the functions and remove
 * duplication: https://github.com/awslabs/s2n/issues/1189
 */
int s2n_server_encrypted_extensions_parse(struct s2n_connection *conn, struct s2n_blob *extensions)
{
    struct s2n_stuffer in = {0};

    GUARD(s2n_stuffer_init(&in, extensions));
    GUARD(s2n_stuffer_write(&in, extensions));

    while (s2n_stuffer_data_available(&in)) {
        struct s2n_blob ext = {0};
        uint16_t extension_type, extension_size;
        struct s2n_stuffer extension = {0};

        GUARD(s2n_stuffer_read_uint16(&in, &extension_type));
        GUARD(s2n_stuffer_read_uint16(&in, &extension_size));

        ext.size = extension_size;
        ext.data = s2n_stuffer_raw_read(&in, ext.size);
        notnull_check(ext.data);

        GUARD(s2n_stuffer_init(&extension, &ext));
        GUARD(s2n_stuffer_write(&extension, &ext));

        switch (extension_type) {
        case TLS_EXTENSION_SERVER_NAME:
            GUARD(s2n_recv_server_server_name(conn, &extension));
            break;
        case TLS_EXTENSION_ALPN:
            GUARD(s2n_recv_server_alpn(conn, &extension));
            break;
        case TLS_EXTENSION_MAX_FRAG_LEN:
            GUARD(s2n_recv_server_max_fragment_length(conn, &extension));
            break;
        /* Error on known extensions that are not supposed to appear in EE
         * https://tools.ietf.org/html/rfc8446#page-37
         */
        case TLS_EXTENSION_RENEGOTIATION_INFO:
        case TLS_EXTENSION_STATUS_REQUEST:
        case TLS_EXTENSION_SESSION_TICKET:
        case TLS_EXTENSION_SUPPORTED_VERSIONS:
        case TLS_EXTENSION_KEY_SHARE:
        case TLS_EXTENSION_SCT_LIST:
            S2N_ERROR(S2N_ERR_BAD_MESSAGE);
            break;
        }
    }

    return 0;
}
