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

#include "tls/s2n_tls13.h"
#include "tls/s2n_tls.h"

#include "testlib/s2n_testlib.h"

#include "utils/s2n_safety.h"


int main(int argc, char **argv)
{
    struct s2n_connection *server_conn;
    struct s2n_cert_chain_and_key *rsa_cert_chain;
    struct s2n_cert_chain_and_key *ecdsa_cert_chain;
    struct s2n_config *tls13_config;

    /* A tls13 client hello with a signature_algorithms_cert extension added. The
    * contents of the extension are the same as the contents of the signature_algorithms extension.
    */
    S2N_BLOB_FROM_HEX(tls13_client_hello_sig_alg_cert, 
    "03030aaa091af267" "f46219ebbf99aaa2" "ebd946f4493921d8" "4c5004f9884b5e77" "b23200001a130213"
    "011303c02fc030cc" "a8c013c027c01400" "9c003c002f00ff01" "000147002b000908" "0304030303020301"
    "003300d000ce001d" "002029b83c98949c" "276da85fc6a956af" "75a1d60c12729296" "710d273563c0487b"
    "793f0017004104c1" "a9ba3876cf6dc6f8" "c7ed8650cebd6023" "9894af2cfd38decd" "3786177a6bc0da2d"
    "d7c59c966182712b" "763741550777a18c" "3b78f8c906061baf" "d326e0cc2c5e6e00" "18006104d010e6e4"
    "685ea1e9bf3dd886" "99609437fb89c9bd" "cd2d88c29b11478d" "54f47511a88a2914" "2870d52eaecdd0a4"
    "06ff9728b38ab5c8" "2ba9b6a1943e9428" "ae44686bb9eed8dd" "6f4f5fa1bb262ca8" "c278b03c51433762"
    "feaba4ce1b40c4c4" "69b38a9e000d0026" "00240809080a080b" "0804080508060401" "0501060103010403"
    "0403050305030603" "030302010203000a" "00080006001d0017" "0018000b00020100" "0032002600240809"
    "080a080b08040805" "0806040105010601" "0301040304030503" "0503060303030201" "0203");

    /* A tls13 client hello with a signature_algorithms_cert extension added. The signature algorithms
     * cert extension only contains ecdsa signature algorithms.
    */
    S2N_BLOB_FROM_HEX(tls13_client_hello_sig_alg_cert_no_rsa, 
    "03030249a87cfe58" "2a7c43a28a6442e9" "d94310bdb1e05457" "ef56389fcc81e8bd" "be1600001a130213"
    "011303c02fc030cc" "a8c013c027c01400" "9c003c002f00ff01" "000133002b000908" "0304030303020301"
    "003300d000ce001d" "0020a88ad32dba59" "1b334c7b8d6cd309" "940b4fac989f0e59" "30f047f98a82ed5a"
    "3952001700410414" "d2fbc2632cd4a846" "3d179c4f3dcfa57b" "6b8875c3deb914a4" "9e79f9e001bb5ad6"
    "9b06eb8a6c4a11d6" "34892baeab3dbeb3" "41b58b70bd4b2606" "669df86541dc2300" "180061049a2e276e"
    "991bcca58e84b2ee" "d41199b8ac7f29f9" "3edf83db52a71760" "992758a6ed7a10d0" "d7f76c1447804591"
    "586db89418b4e026" "3f663c37349d6fd0" "9ff2ef55af87b4c6" "5a9072b1536d2b92" "abbb326b1050094a"
    "b20e13980d17e5c9" "26654743000d0026" "00240809080a080b" "0804080508060401" "0501060103010403"
    "0403050305030603" "030302010203000a" "00080006001d0017" "0018000b00020100" "0032001200100403"
    "0403050305030603" "030302010203");

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13());

   
    EXPECT_NOT_NULL(tls13_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(tls13_config, "test_all"));
    
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_cert_chain,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_cert_chain,
            S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));

    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(tls13_config, rsa_cert_chain));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(tls13_config, ecdsa_cert_chain));

    /* s2n_client_hello_recv can process a signature_algorithms_cert extension */
    {
        /* signature_algorithms_cert extension contains same information as signature_algorithms extension */
        {
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls13_config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

            EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &tls13_client_hello_sig_alg_cert));
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

            /* The sig alg choosen for the server cert and for the Certificate Verify message should be equal */
            EXPECT_EQUAL(server_conn->secure.conn_sig_scheme.sig_alg, S2N_SIGNATURE_RSA_PSS_RSAE);
            EXPECT_EQUAL(server_conn->secure.client_signature_algorithms_cert.sig_alg, S2N_SIGNATURE_RSA_PSS_RSAE);
            s2n_connection_free(server_conn);
        }
        
        /* signature_algorithms_cert extension is not the same as the signature_algorithms extension */
        {   
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls13_config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

            EXPECT_SUCCESS(s2n_stuffer_write(&server_conn->handshake.io, &tls13_client_hello_sig_alg_cert_no_rsa));
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

            /* The sig alg choosen for the server cert and for the Certificate Verify message should be equal */
            EXPECT_EQUAL(server_conn->secure.conn_sig_scheme.sig_alg, S2N_SIGNATURE_RSA_PSS_RSAE);
            EXPECT_EQUAL(server_conn->secure.client_signature_algorithms_cert.sig_alg, S2N_SIGNATURE_ECDSA);

            s2n_connection_free(server_conn);
        }
    }

    s2n_config_free(tls13_config);
    
    END_TEST();
    return S2N_SUCCESS;
}
