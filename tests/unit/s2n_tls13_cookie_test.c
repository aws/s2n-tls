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

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <s2n.h>

#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"

#include "tls/extensions/s2n_cookie.h"

#include "utils/s2n_safety.h"

#define EXTENSION_LEN       2
#define EXTENSION_DATA_LEN  2
#define COOKIE_SIZE_LEN     2
#define COOKIE_TEST_SIZE    16

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    {
        EXPECT_SUCCESS(s2n_enable_tls13());

        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        uint8_t cookie_data_compare[COOKIE_TEST_SIZE] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5 };
        struct s2n_blob compare_blob;
        EXPECT_SUCCESS(s2n_blob_init(&compare_blob, cookie_data_compare, COOKIE_TEST_SIZE));

        /* Test that cookies are not implemented until HelloRetryRequests are available */
        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_client_cookie_recv(NULL, NULL), S2N_ERR_UNIMPLEMENTED);
        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_client_cookie_send(NULL, NULL), S2N_ERR_UNIMPLEMENTED);
        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_server_cookie_recv(NULL, NULL), S2N_ERR_UNIMPLEMENTED);
        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_server_cookie_send(NULL, NULL), S2N_ERR_UNIMPLEMENTED);

        /* Test that we can send and receive a cookie extension */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Initialize the connection's cookie data with a default value.
             * The server will send this value in the cookie extension. */
            EXPECT_SUCCESS(s2n_stuffer_resize(&conn->cookie_stuffer, COOKIE_TEST_SIZE));
            EXPECT_SUCCESS(s2n_stuffer_write(&conn->cookie_stuffer, &compare_blob));

            /* Initialize the extension stuff which will be written to */
            struct s2n_blob out_blob;
            struct s2n_stuffer out_stuffer;
            uint8_t extension_out[EXTENSION_LEN + EXTENSION_DATA_LEN + COOKIE_SIZE_LEN + COOKIE_TEST_SIZE] = { 0 };

            /* Send the extension and verify the expected number of bytes were written */
            EXPECT_SUCCESS(s2n_blob_init(&out_blob, extension_out, sizeof(extension_out)));
            EXPECT_SUCCESS(s2n_stuffer_init(&out_stuffer, &out_blob));
            EXPECT_SUCCESS(s2n_extensions_cookie_send(conn, &out_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(&out_stuffer, EXTENSION_LEN + EXTENSION_DATA_LEN + COOKIE_SIZE_LEN + COOKIE_TEST_SIZE);

            /* Reset the extension stuffer and cookie data */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->cookie_stuffer));
            EXPECT_SUCCESS(s2n_stuffer_reread(&out_stuffer));
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&out_stuffer, EXTENSION_LEN));
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&out_stuffer, EXTENSION_DATA_LEN));

            /* Verify we can receive the extension and the cookie_data is set correctly */
            EXPECT_SUCCESS(s2n_extensions_cookie_recv(conn, &out_stuffer));
            S2N_BLOB_EXPECT_EQUAL(conn->cookie_stuffer.blob, compare_blob);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that cookies with incorrect size fields don't get processed */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Initialize the extension stuff which will be written to */
            struct s2n_blob out_blob;
            struct s2n_stuffer out_stuffer;
            uint8_t extension_out[EXTENSION_LEN + EXTENSION_DATA_LEN + COOKIE_SIZE_LEN + COOKIE_TEST_SIZE] = { 0 };

            EXPECT_SUCCESS(s2n_blob_init(&out_blob, extension_out, sizeof(extension_out)));
            EXPECT_SUCCESS(s2n_stuffer_init(&out_stuffer, &out_blob));

            /* This cookie says it has 3 bytes, but only has 2 bytes */
            uint8_t bad_size[5] = { TLS_EXTENSION_COOKIE, 0x00, 0x03, 0x00, 0x00 };
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&out_stuffer, bad_size, sizeof(bad_size)));

            /* The receive should succeed, but since the extension was corrupted it 
             * should not be saved to the connection. */
            EXPECT_SUCCESS(s2n_extensions_cookie_recv(conn, &out_stuffer));
            EXPECT_EQUAL(s2n_extensions_cookie_size(conn), 0);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_disable_tls13());
    }

    END_TEST();
    return 0;
}
