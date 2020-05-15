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

#include "tls/s2n_key_update.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls13_handshake.h"
#include "tls/s2n_cipher_suites.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

int main(int argc, char **argv)
{
     /* KeyUpdate Vectors from Openssl s_client implemenation of KeyUpdate. The ciphersuite
      * that produced this secret was s2n_tls13_aes_256_gcm_sha384. 
      */
    
    S2N_BLOB_FROM_HEX(application_secret,
        "4bc28934ddd802b00f479e14a72d7725dab45d32b3b145f29"
        "e4c5b56677560eb5236b168c71c5c75aa52f3e20ee89bfb"); 
        
    S2N_BLOB_FROM_HEX(updated_application_secret,
        "ee85dd54781bd4d8a100589a9fe6ac9a3797b811e977f549cd"
        "531be2441d7c63e2b9729d145c11d84af35957727565a4");

    BEGIN_TEST();

    /* This test checks the new secret produced by the s2n_tls13_update_application_traffic_keys
     * is the same one that is produced by openssl when starting with the same application secret. 
     */
    { 
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS13;
        conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

        /* Store application secret */
        struct s2n_stuffer application_secret_stuffer = {0};
        struct s2n_blob application_secret_blob = {0};
        EXPECT_SUCCESS(s2n_blob_init(&application_secret_blob, conn->secure.client_app_secret, sizeof(conn->secure.client_app_secret)));
        EXPECT_SUCCESS(s2n_stuffer_init(&application_secret_stuffer, &application_secret_blob));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&application_secret_stuffer, application_secret.data, application_secret.size));

        EXPECT_SUCCESS(s2n_update_application_traffic_keys(conn, S2N_CLIENT, RECEIVING));

        /* Check the new secret is what was expected */
        S2N_BLOB_EXPECT_EQUAL(application_secret_stuffer.blob, updated_application_secret); 
        EXPECT_SUCCESS(s2n_connection_free(conn)); 

    }
    END_TEST();
}

