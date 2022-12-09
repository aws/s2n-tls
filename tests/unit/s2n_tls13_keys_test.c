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

#include "crypto/s2n_tls13_keys.h"

#include <string.h>

#include "crypto/s2n_hkdf.h"
#include "crypto/s2n_hmac.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /*
     * Test s2n_tls13_update_application_traffic_secret
     *
     * This test checks the new secret produced by the s2n_tls13_update_application_traffic_secret
     * is the same one that is produced by openssl when starting with the same application secret.
     */
    {
        /* KeyUpdate Vectors from Openssl s_client implementation of KeyUpdate. The ciphersuite
         * that produced this secret was s2n_tls13_aes_256_gcm_sha384.
         */
        S2N_BLOB_FROM_HEX(application_secret,
                "4bc28934ddd802b00f479e14a72d7725dab45d32b3b145f29"
                "e4c5b56677560eb5236b168c71c5c75aa52f3e20ee89bfb");
        S2N_BLOB_FROM_HEX(updated_application_secret,
                "ee85dd54781bd4d8a100589a9fe6ac9a3797b811e977f549cd"
                "531be2441d7c63e2b9729d145c11d84af35957727565a4");

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS13;
        server_conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

        /* get tls13 key context */
        s2n_tls13_connection_keys(keys, server_conn);

        s2n_stack_blob(app_secret_update, keys.size, S2N_TLS13_SECRET_MAX_LEN);

        /* Derives next generation of traffic secret */
        EXPECT_SUCCESS(s2n_tls13_update_application_traffic_secret(&keys, &application_secret, &app_secret_update));

        /* Check the new secret is what was expected */
        S2N_BLOB_EXPECT_EQUAL(app_secret_update, updated_application_secret);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    END_TEST();
}
