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
#include "utils/s2n_safety.h"

#define S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH 3

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_cert_chain_and_key *chain_and_key = NULL;
    EXPECT_SUCCESS(
        s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* Test s2n_get_cert_chain_length */ 
    {
        uint32_t length = 0;
        EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_chain_length(NULL, &length), S2N_ERR_NULL);
        EXPECT_SUCCESS(s2n_get_cert_chain_length(chain_and_key, &length));
        EXPECT_EQUAL(length, S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH);
    }

    /* Test s2n_get_cert_from_cert_chain */
    {
        struct s2n_cert *out_cert = NULL;
        uint32_t cert_idx = 0;

        /* Safety checks */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_from_cert_chain(NULL, &out_cert, cert_idx), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_from_cert_chain(chain_and_key, NULL, cert_idx), S2N_ERR_NULL);
            /* The valid range of cert_idx is 0 to cert_chain_length - 1 */  
            cert_idx = S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH; 
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_from_cert_chain(chain_and_key, &out_cert, cert_idx), S2N_ERR_SAFETY);
        }

        struct s2n_cert *cur_cert = chain_and_key->cert_chain->head;

        for (size_t i = 0; i < S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH; i++)
        {
            EXPECT_SUCCESS(s2n_get_cert_from_cert_chain(chain_and_key, &out_cert, i));
            EXPECT_NOT_NULL(cur_cert);
            EXPECT_EQUAL(out_cert, cur_cert);
            cur_cert = cur_cert->next;
        }
    }

    /* Test s2n_get_cert_der */ 
    {
        struct s2n_cert *cert = chain_and_key->cert_chain->head;
        uint8_t *out_cert_der = NULL;
        uint32_t cert_len = 0;

        /* Safety checks */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_der(NULL, &out_cert_der, &cert_len), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_der(cert, NULL, &cert_len), S2N_ERR_NULL);
        }

        EXPECT_SUCCESS(s2n_get_cert_der(cert, &out_cert_der, &cert_len));
        EXPECT_EQUAL(cert_len, cert->raw.size); 
        EXPECT_BYTEARRAY_EQUAL(out_cert_der, cert->raw.data, cert_len);
    }

    /* Test s2n_connection_get_peer_cert_chain */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        POSIX_ENSURE_REF(conn);

        struct s2n_cert_chain_and_key *cert_chain_and_key = NULL;
        EXPECT_NULL(conn->handshake_params.our_chain_and_key);

        /* Safety checks */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(NULL, &cert_chain_and_key), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(conn, &cert_chain_and_key), S2N_ERR_NULL);
        }

        /* Initialize cert chain */
        conn->handshake_params.our_chain_and_key = chain_and_key;
        EXPECT_SUCCESS(s2n_connection_get_peer_cert_chain(conn, &cert_chain_and_key));
        EXPECT_EQUAL(chain_and_key, cert_chain_and_key); 

        EXPECT_SUCCESS(s2n_connection_free(conn));       
    }

    END_TEST();
}
