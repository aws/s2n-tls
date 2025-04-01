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

#include "crypto/s2n_pkey.h"

#include "crypto/s2n_rsa_pss.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

struct s2n_test_pkeys {
    struct s2n_pkey pub_key;
    struct s2n_pkey *priv_key;
    bool supported;
};

S2N_RESULT s2n_test_pkeys_init(struct s2n_test_pkeys *pkeys,
        const char *cert_chain_file, const char *private_key_file)
{
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    RESULT_GUARD_POSIX(s2n_test_cert_chain_and_key_new(&chain_and_key,
            cert_chain_file, private_key_file));

    /* Take ownership of the private key */
    pkeys->priv_key = chain_and_key->private_key;
    chain_and_key->private_key = NULL;

    /* We parse the public key when we create the cert chain and key,
     * BUT we don't actually store it anywhere. So recreate it.
     */
    s2n_pkey_type type = 0;
    RESULT_GUARD(s2n_asn1der_to_public_key_and_type(&pkeys->pub_key, &type,
            &chain_and_key->cert_chain->head->raw));

    pkeys->supported = true;
    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_test_pkeys_wipe(struct s2n_test_pkeys *pkeys)
{
    if (!pkeys) {
        return S2N_RESULT_OK;
    }
    RESULT_GUARD_POSIX(s2n_pkey_free(&pkeys->pub_key));
    RESULT_GUARD_POSIX(s2n_pkey_free(pkeys->priv_key));
    RESULT_GUARD_POSIX(s2n_free_object((uint8_t **) &pkeys->priv_key, sizeof(struct s2n_pkey)));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_test_pkeys ecdsa_pkeys = { 0 }, s2n_test_pkeys_wipe);
    EXPECT_OK(s2n_test_pkeys_init(&ecdsa_pkeys,
            S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));

    DEFER_CLEANUP(struct s2n_test_pkeys rsa_pkeys = { 0 }, s2n_test_pkeys_wipe);
    EXPECT_OK(s2n_test_pkeys_init(&rsa_pkeys,
            S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN, S2N_RSA_2048_PKCS1_SHA256_CERT_KEY));

    DEFER_CLEANUP(struct s2n_test_pkeys rsa_pss_pkeys = { 0 }, s2n_test_pkeys_wipe);
    if (s2n_is_rsa_pss_certs_supported()) {
        EXPECT_OK(s2n_test_pkeys_init(&rsa_pss_pkeys,
                S2N_RSA_PSS_2048_SHA256_LEAF_CERT, S2N_RSA_PSS_2048_SHA256_LEAF_KEY));
    }

    struct s2n_test_pkeys test_pkeys[] = { ecdsa_pkeys, rsa_pkeys, rsa_pss_pkeys };

    /* Test s2n_pkey_match */
    {
        DEFER_CLEANUP(struct s2n_test_pkeys other_ecdsa_pkeys = { 0 }, s2n_test_pkeys_wipe);
        EXPECT_OK(s2n_test_pkeys_init(&other_ecdsa_pkeys,
                S2N_ECDSA_P256_PKCS1_CERT_CHAIN, S2N_ECDSA_P256_PKCS1_KEY));

        DEFER_CLEANUP(struct s2n_test_pkeys other_rsa_pkeys = { 0 }, s2n_test_pkeys_wipe);
        EXPECT_OK(s2n_test_pkeys_init(&other_rsa_pkeys,
                S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY));

        DEFER_CLEANUP(struct s2n_test_pkeys other_rsa_pss_pkeys = { 0 }, s2n_test_pkeys_wipe);
        if (s2n_is_rsa_pss_certs_supported()) {
            EXPECT_OK(s2n_test_pkeys_init(&other_rsa_pss_pkeys,
                    S2N_RSA_PSS_2048_SHA256_CA_CERT, S2N_RSA_PSS_2048_SHA256_CA_KEY));
        }

        struct s2n_test_pkeys other_pkeys[] = {
            other_ecdsa_pkeys, other_rsa_pkeys, other_rsa_pss_pkeys
        };

        for (size_t pkey_i = 0; pkey_i < s2n_array_len(test_pkeys); pkey_i++) {
            if (!test_pkeys[pkey_i].supported) {
                continue;
            }

            EXPECT_SUCCESS(s2n_pkey_match(
                    &test_pkeys[pkey_i].pub_key,
                    test_pkeys[pkey_i].priv_key));

            for (size_t other_i = 0; other_i < s2n_array_len(other_pkeys); other_i++) {
                if (!other_pkeys[other_i].supported) {
                    continue;
                }

                EXPECT_FAILURE_WITH_ERRNO(
                        s2n_pkey_match(&test_pkeys[pkey_i].pub_key, other_pkeys[other_i].priv_key),
                        S2N_ERR_KEY_MISMATCH);
                EXPECT_FAILURE_WITH_ERRNO(
                        s2n_pkey_match(&other_pkeys[other_i].pub_key, test_pkeys[pkey_i].priv_key),
                        S2N_ERR_KEY_MISMATCH);
            }
        }
    };

    END_TEST();
}
