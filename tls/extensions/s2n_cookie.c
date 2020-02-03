/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/extensions/s2n_cookie.h"

int s2n_cookie_len(struct s2n_connection *conn)
{
    return s2n_stuffer_data_available(&conn->cookie_stuffer);
}

int s2n_cookie_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint16_t cookie_len;

    GUARD(s2n_stuffer_read_uint16(extension, &cookie_len));

    if (s2n_stuffer_data_available(extension) != cookie_len) {
        return 0;
    }

    GUARD(s2n_stuffer_wipe(&conn->cookie_stuffer));
    GUARD(s2n_stuffer_resize(&conn->cookie_stuffer, cookie_len));
    GUARD(s2n_stuffer_copy(extension, &conn->cookie_stuffer, cookie_len));

    return 0;
}

int s2n_cookie_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    notnull_check(conn);
    notnull_check(out);

    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_COOKIE));
    GUARD(s2n_stuffer_write_uint16(out, s2n_cookie_len(conn)));
    GUARD(s2n_stuffer_copy(&conn->cookie_stuffer, out, s2n_cookie_len(conn)));

    return 0;
}
