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

#include "crypto/s2n_pkey_mldsa.h"

#include "crypto/s2n_libcrypto.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#define S2N_MLDSA_FILE_PREFIX      "../pems/mldsa/ML-DSA-"
#define S2N_MLDSA_PUB_SUFFIX       ".crt"
#define S2N_MLDSA_PRIV_SEED_SUFFIX "-seed.priv"
#define S2N_MLDSA_EXPANDED_SUFFIX  "-expanded.priv"
#define S2N_MLDSA_BOTH_SUFFIX      "-both.priv"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* The AWSLC API version was bumped to 32 when ML-DSA support was added.
     * See https://github.com/aws/aws-lc/commit/404fe0f8a79ca0f28118990a06e921b63035991c
     */
    if (s2n_libcrypto_awslc_api_version() >= 32) {
        EXPECT_TRUE(s2n_pkey_mldsa_supported());
    }

    if (!s2n_pkey_mldsa_supported()) {
        END_TEST();
    }

    const char *key_sizes[] = { "44", "65", "87" };
    const char *suffixes[] = {
        S2N_MLDSA_PRIV_SEED_SUFFIX,
        S2N_MLDSA_EXPANDED_SUFFIX,
        /* AWS-LC does not currently support the "both" key format,
         * so s2n-tls does not currently support the "both" key format.
         * S2N_MLDSA_BOTH_SUFFIX,
         */
    };

    /* Test: s2n-tls can load cert chains with private keys in all ML-DSA formats */
    for (size_t size_i = 0; size_i < s2n_array_len(key_sizes); size_i++) {
        const char *key_size = key_sizes[size_i];

        for (size_t suffix_i = 0; suffix_i < s2n_array_len(suffixes); suffix_i++) {
            const char *suffix = suffixes[suffix_i];

            char pub_key_path[100] = { 0 };
            snprintf(pub_key_path, sizeof(pub_key_path), "%s%s%s",
                    S2N_MLDSA_FILE_PREFIX, key_size, S2N_MLDSA_PUB_SUFFIX);

            char priv_key_path[100] = { 0 };
            snprintf(priv_key_path, sizeof(priv_key_path), "%s%s%s",
                    S2N_MLDSA_FILE_PREFIX, key_size, suffix);

            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain,
                    pub_key_path, priv_key_path));

            EXPECT_NOT_NULL(chain);
            EXPECT_NOT_NULL(chain->private_key);
            EVP_PKEY *pkey = chain->private_key->pkey;
            EXPECT_NOT_NULL(pkey);

            s2n_pkey_type pkey_type = 0;
            EXPECT_OK(s2n_pkey_get_type(pkey, &pkey_type));
            EXPECT_EQUAL(pkey_type, S2N_PKEY_TYPE_MLDSA);
        }
    }

    END_TEST();
}
