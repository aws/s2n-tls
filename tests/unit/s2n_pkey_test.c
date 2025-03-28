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

/* The rsa encrypt/decrypt methods are static.
 * This is temporary, and will be removed when legacy rsa pkeys are removed.
 * We do the same to test signing.
 */
#include "crypto/s2n_rsa.c"

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

    /* Test s2n_pkey_size */
    {
        /* Compare to known values */
        uint32_t expected_sizes[] = { 104, 256, 256 };
        EXPECT_EQUAL(s2n_array_len(test_pkeys), s2n_array_len(expected_sizes));

        for (size_t i = 0; i < s2n_array_len(test_pkeys); i++) {
            if (!test_pkeys[i].supported) {
                continue;
            }

            uint32_t pub_size = 0;
            EXPECT_OK(s2n_pkey_size(&test_pkeys[i].pub_key, &pub_size));
            EXPECT_EQUAL(pub_size, expected_sizes[i]);

            uint32_t priv_size = 0;
            EXPECT_OK(s2n_pkey_size(test_pkeys[i].priv_key, &priv_size));
            EXPECT_EQUAL(priv_size, expected_sizes[i]);
        }
    };

    /* Test: s2n_pkey_encrypt / s2n_pkey_decrypt */
    {
        struct s2n_blob in = { 0 }, out = { 0 };

        /* Test: not supported for ECDSA */
        {
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_pkey_encrypt(ecdsa_pkeys.priv_key, &in, &out),
                    S2N_ERR_UNIMPLEMENTED);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_pkey_decrypt(&ecdsa_pkeys.pub_key, &in, &out),
                    S2N_ERR_UNIMPLEMENTED);
        };

        /* Test: not supported for RSA-PSS */
        if (rsa_pss_pkeys.supported) {
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_pkey_encrypt(rsa_pss_pkeys.priv_key, &in, &out),
                    S2N_ERR_UNIMPLEMENTED);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_pkey_decrypt(&rsa_pss_pkeys.pub_key, &in, &out),
                    S2N_ERR_UNIMPLEMENTED);
        };

        /* Test: supported for RSA */
        {
            uint8_t message_bytes[] = "hello world";
            struct s2n_blob message = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&message, message_bytes, sizeof(message_bytes)));

            const char ciphertext_hex[] =
                    "38 ab 9c 83 57 17 13 46 3d 5b 6f c6 44 30 8e 40 78 ac d2 "
                    "c5 69 98 8b 99 51 14 23 c6 af 98 67 6f 58 d5 28 9e 23 12 "
                    "6f 5b 73 56 d9 f9 b2 10 4f d6 53 5c 70 a5 a6 c6 a2 53 83 "
                    "7d ec 3b 7c c0 ff 6a 30 8d 98 a3 6c be c6 e3 b4 4d b6 3d "
                    "cc 94 67 f8 24 9a 91 13 52 57 02 0c d9 5a 00 98 1f ff df "
                    "5e 47 e0 ca 15 87 f0 92 1e 95 af ef 49 b2 6b f2 b6 be d5 "
                    "3b 65 d3 94 92 f5 c1 f0 65 56 20 85 7f 18 95 a5 d9 e7 6c "
                    "43 07 dd 5d 03 60 ac 4d c5 a0 c8 3d f9 99 24 fc 30 8f c2 "
                    "66 9d df 5c 80 90 a7 c5 7a 37 ee be 1d 30 a7 a3 67 73 ae "
                    "7d ee 64 37 22 77 9a a5 0d 47 f0 a5 50 ee 85 82 2e 88 32 "
                    "e9 0b bc 25 5f 09 b7 d3 13 58 88 84 9d 07 03 5e 37 6b af "
                    "08 56 14 fd 64 58 29 5b 81 a5 72 72 62 5d c1 72 bb 13 76 "
                    "b6 17 96 7b d9 87 ec 49 71 dc 33 3e b2 f5 76 54 ad 13 ed "
                    "23 1c 34 53 d1 12 03 be f6";
            S2N_BLOB_FROM_HEX(ciphertext, ciphertext_hex);

            /* Test: legacy RSA decryption accepts known good value */
            {
                DEFER_CLEANUP(struct s2n_blob output = { 0 }, s2n_free);
                EXPECT_SUCCESS(s2n_alloc(&output, message.size));

                EXPECT_SUCCESS(s2n_rsa_decrypt(rsa_pkeys.priv_key, &ciphertext, &output));
                EXPECT_BYTEARRAY_EQUAL(output.data, message.data, message.size);
            };

            /* Test: decryption works for known good value */
            {
                DEFER_CLEANUP(struct s2n_blob output = { 0 }, s2n_free);
                EXPECT_SUCCESS(s2n_alloc(&output, message.size));

                EXPECT_SUCCESS(s2n_pkey_decrypt(rsa_pkeys.priv_key, &ciphertext, &output));
                EXPECT_BYTEARRAY_EQUAL(output.data, message.data, message.size);
            };

            /* Test: decryption works for result of encryption */
            {
                DEFER_CLEANUP(struct s2n_blob encrypt_out = { 0 }, s2n_free);
                EXPECT_SUCCESS(s2n_alloc(&encrypt_out, ciphertext.size));
                EXPECT_SUCCESS(s2n_pkey_encrypt(&rsa_pkeys.pub_key, &message, &encrypt_out));

                DEFER_CLEANUP(struct s2n_blob decrypt_out = { 0 }, s2n_free);
                EXPECT_SUCCESS(s2n_alloc(&decrypt_out, message.size));
                EXPECT_SUCCESS(s2n_pkey_decrypt(rsa_pkeys.priv_key, &encrypt_out, &decrypt_out));
            };
        };
    };

    END_TEST();
}
