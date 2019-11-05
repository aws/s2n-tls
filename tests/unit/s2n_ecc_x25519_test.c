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

#include "crypto/s2n_ecc_x25519.h"
#include "utils/s2n_mem.h"
#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    {
        /* Test compute shared sceret for Curve25519 */
        struct s2n_ecc_evp_params server_params, client_params;
        struct s2n_stuffer out;
        struct s2n_blob server_shared, client_shared;

        const struct s2n_ecc_named_curve *curve = &s2n_X25519;
        server_params.negotiated_curve = curve;

        EXPECT_SUCCESS(s2n_stuffer_alloc(&out, curve->share_size + 4));

        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&out, server_params.negotiated_curve->iana_id));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&out, server_params.negotiated_curve->share_size));

        /* Server generates a key */
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_params));

        /* Client generates a key, computes its shared secret and sends the client public key */
        EXPECT_SUCCESS(s2n_ecc_evp_compute_shared_secret_as_client(&server_params, &client_params, &client_shared));

        /* Server receives the client public key and computes its shared secret */
        EXPECT_SUCCESS(s2n_ecc_evp_compute_shared_secret_as_server(&server_params, &client_params, &server_shared));

        /* Check if the shared secret computed is the same for the client and the server */
        EXPECT_EQUAL(client_shared.size, server_shared.size);
        EXPECT_BYTEARRAY_EQUAL(client_shared.data, server_shared.data, client_shared.size);

        /* Clean up */
        EXPECT_SUCCESS(s2n_stuffer_free(&out));
        EXPECT_SUCCESS(s2n_free(&server_shared));
        EXPECT_SUCCESS(s2n_free(&client_shared));
        EXPECT_SUCCESS(s2n_ecc_evp_params_free(&server_params));
        EXPECT_SUCCESS(s2n_ecc_evp_params_free(&client_params));
    }

    END_TEST();
}

