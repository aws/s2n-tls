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

#include <stdint.h>
#include "api/s2n.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#include "tls/s2n_tls.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

const uint8_t test_signature_data[] = "I signed this";
const uint32_t test_signature_size = sizeof(test_signature_data);
const uint32_t test_max_signature_size = 2 * sizeof(test_signature_data);

static S2N_RESULT test_size(const struct s2n_pkey *pkey, uint32_t *size_out)
{
    *size_out = test_max_signature_size;
    return S2N_RESULT_OK;
}

static int test_sign(const struct s2n_pkey *priv_key, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    POSIX_CHECKED_MEMCPY(signature->data, test_signature_data, test_signature_size);
    signature->size = test_signature_size;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test that the signature size is written correctly when not equal to the maximum */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        /* Set any signature scheme. Our test pkey methods ignore it. */
        conn->secure.client_cert_sig_scheme = s2n_rsa_pkcs1_md5_sha1;

        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        chain_and_key->private_key->size = test_size;
        chain_and_key->private_key->sign = test_sign;
        conn->handshake_params.our_chain_and_key = chain_and_key;

        EXPECT_SUCCESS(s2n_client_cert_verify_send(conn));

        uint16_t signature_scheme_iana;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&conn->handshake.io, &signature_scheme_iana));
        EXPECT_EQUAL(signature_scheme_iana, s2n_rsa_pkcs1_md5_sha1.iana_value);

        uint16_t signature_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&conn->handshake.io, &signature_size));
        EXPECT_NOT_EQUAL(signature_size, test_max_signature_size);
        EXPECT_EQUAL(signature_size, test_signature_size);
        EXPECT_EQUAL(signature_size, s2n_stuffer_data_available(&conn->handshake.io));

        uint8_t *signature_data = s2n_stuffer_raw_read(&conn->handshake.io, test_signature_size);
        EXPECT_NOT_NULL(signature_data);
        EXPECT_BYTEARRAY_EQUAL(signature_data, test_signature_data, test_signature_size);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    }

    END_TEST();
}
