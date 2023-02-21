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
#include "tls/extensions/s2n_server_cert_status_request.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Extension should not be sent by default */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        EXPECT_FALSE(s2n_server_cert_status_request_extension.should_send(conn));
    }

    /* Extension should be sent if OCSP stapling is supported and was requested  */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        if (s2n_x509_ocsp_stapling_supported()) {
            EXPECT_SUCCESS(s2n_config_set_status_request_type(config, S2N_STATUS_REQUEST_OCSP));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_TRUE(s2n_server_cert_status_request_extension.should_send(conn));
        } else {
            /* Requesting OCSP stapling should not be possible if not supported */
            EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_status_request_type(config, S2N_STATUS_REQUEST_OCSP),
                    S2N_ERR_OCSP_NOT_SUPPORTED);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_FALSE(s2n_server_cert_status_request_extension.should_send(conn));
        }
    }

    /* Extension should be empty */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_server_cert_status_request_extension.send(conn, &stuffer));

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
    }

    END_TEST();
}
