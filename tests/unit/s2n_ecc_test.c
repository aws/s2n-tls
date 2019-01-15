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

#include "s2n_test.h"

#include <s2n.h>

#include "crypto/s2n_ecc.h"
#include "utils/s2n_mem.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test generate->write->read->compute_shared with all supported curves */
    for (int i = 0; i < sizeof(s2n_ecc_supported_curves) / sizeof(s2n_ecc_supported_curves[0]); i++) {
        struct s2n_ecc_params server_params, client_params;
        struct s2n_stuffer wire;
        struct s2n_blob server_shared, client_shared, ecdh_params_sent, ecdh_params_received;

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 1024));

        /* Server generates a key for a given curve */
        server_params.negotiated_curve = &s2n_ecc_supported_curves[i];
        EXPECT_SUCCESS(s2n_ecc_generate_ephemeral_key(&server_params));
        /* Server sends the public */
        EXPECT_SUCCESS(s2n_ecc_write_ecc_params(&server_params, &wire, &ecdh_params_sent));
        /* Client reads the public */
        struct s2n_ecdhe_raw_server_params ecdhe_data = {{0}};
        EXPECT_SUCCESS(s2n_ecc_read_ecc_params(&wire, &ecdh_params_received, &ecdhe_data));
        EXPECT_SUCCESS(s2n_ecc_parse_ecc_params(&client_params, &ecdhe_data));

        /* The client got the curve */
        EXPECT_EQUAL(client_params.negotiated_curve, server_params.negotiated_curve);

        /* Client sends its public */
        EXPECT_SUCCESS(s2n_ecc_compute_shared_secret_as_client(&client_params, &wire, &client_shared));
        /* Server receives it */
        EXPECT_SUCCESS(s2n_ecc_compute_shared_secret_as_server(&server_params, &wire, &server_shared));
        /* Shared is the same for the client and the server */
        EXPECT_EQUAL(client_shared.size, server_shared.size);
        EXPECT_BYTEARRAY_EQUAL(client_shared.data, server_shared.data, client_shared.size);

        /* Clean up */
        EXPECT_SUCCESS(s2n_stuffer_free(&wire));
        EXPECT_SUCCESS(s2n_free(&server_shared));
        EXPECT_SUCCESS(s2n_free(&client_shared));
        EXPECT_SUCCESS(s2n_ecc_params_free(&server_params));
        EXPECT_SUCCESS(s2n_ecc_params_free(&client_params));
    }

    END_TEST();
}
