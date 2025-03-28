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

#include "crypto/s2n_ecdsa.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_libcrypto.h"
#include "crypto/s2n_pkey_evp.h"
#include "crypto/s2n_rsa_pss.h"
#include "crypto/s2n_rsa_signing.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

/* The ecdsa sign/verify methods are static */
#include "crypto/s2n_ecdsa.c"
#include "crypto/s2n_rsa.c"

#define INPUT_DATA_SIZE  100
#define OUTPUT_DATA_SIZE 1000

#define EXPECT_PKEY_USES_EVP_SIGNING(pkey)   \
    EXPECT_EQUAL(pkey->sign, &s2n_evp_sign); \
    EXPECT_EQUAL(pkey->verify, &s2n_evp_verify)

const uint8_t input_data[INPUT_DATA_SIZE] = "hello hash";

static S2N_RESULT s2n_test_hash_init(struct s2n_hash_state *hash_state, s2n_hash_algorithm hash_alg)
{
    RESULT_GUARD_POSIX(s2n_hash_init(hash_state, hash_alg));
    RESULT_GUARD_POSIX(s2n_hash_update(hash_state, input_data, s2n_array_len(input_data)));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_setup_public_key(struct s2n_pkey *public_key, struct s2n_cert_chain_and_key *chain)
{
    s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
    EXPECT_OK(s2n_asn1der_to_public_key_and_type(public_key, &pkey_type,
            &chain->cert_chain->head->raw));
    EXPECT_EQUAL(pkey_type, chain->cert_chain->head->pkey_type);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_evp_sign(s2n_signature_algorithm sig_alg, s2n_hash_algorithm hash_alg,
        struct s2n_pkey *private_key, struct s2n_blob *evp_signature_out)
{
    DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
    RESULT_GUARD_POSIX(s2n_hash_new(&hash_state));
    RESULT_GUARD(s2n_test_hash_init(&hash_state, hash_alg));
    RESULT_GUARD_POSIX(s2n_evp_sign(private_key, sig_alg, &hash_state, evp_signature_out));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_evp_verify(s2n_signature_algorithm sig_alg, s2n_hash_algorithm hash_alg,
        struct s2n_pkey *public_key, struct s2n_blob *expected_signature)
{
    DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
    RESULT_GUARD_POSIX(s2n_hash_new(&hash_state));

    /* Verify that the EVP methods can verify their own signature */
    RESULT_GUARD(s2n_test_hash_init(&hash_state, hash_alg));
    RESULT_GUARD_POSIX(s2n_evp_verify(public_key, sig_alg, &hash_state, expected_signature));

    /* Verify that using the pkey directly can verify own signature */
    RESULT_GUARD(s2n_test_hash_init(&hash_state, hash_alg));
    RESULT_GUARD_POSIX(s2n_pkey_verify(public_key, sig_alg, &hash_state, expected_signature));

    return S2N_RESULT_OK;
}

static bool s2n_test_legacy_signing_supported()
{
    return !s2n_libcrypto_is_openssl_fips();
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_cert_chain_and_key *rsa_cert_chain = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_cert_chain,
            S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY));

    /* Determining all possible valid combinations of hash algorithms and
     * signature algorithms is actually surprisingly complicated.
     *
     * For example: awslc-fips will fail for MD5+ECDSA. However, that is not
     * a real problem because there is no valid signature scheme that uses both
     * MD5 and ECDSA.
     *
     * To avoid enumerating all the exceptions, just use the actual supported
     * signature scheme list as the source of truth.
     */
    const struct s2n_signature_preferences *all_sig_schemes =
            security_policy_test_all.signature_preferences;

    /* EVP signing must match RSA signing */
    {
        s2n_signature_algorithm sig_alg = S2N_SIGNATURE_RSA;

        const char *valid_signatures[S2N_HASH_ALGS_COUNT] = {
            [S2N_HASH_MD5_SHA1] =
                    "59 5b 8b 75 95 16 21 ae a1 7c 63 84 8f 9e 86 fd f9 79 e1 "
                    "d4 8b d7 01 91 37 43 86 75 d0 20 ce 64 31 4e 31 d1 dc dd 7e "
                    "a4 f3 86 36 8f d8 36 ef 27 7c 6b 09 8c e2 8b 35 79 c4 c0 a9 "
                    "f5 c1 ae 22 fd a8 23 83 af 52 4a 61 fe f5 14 c7 7c 7d fe af "
                    "11 bf 6b 6a 4a 3a e0 cb 63 24 13 2d 8d c3 6b b3 51 bb 1b f4 "
                    "d3 1b b2 67 bd 4c ad 7e b5 eb eb 52 fd 42 78 41 ef 40 c5 ba "
                    "42 1a 72 5a 45 3a 92 fd ff 43 6a 38 dd b9 de 13 32 34 4d 58 "
                    "77 53 56 96 bd 93 98 87 de 3d 6e 53 2e ff ea 01 71 97 dd a6 "
                    "62 02 9d 9c 58 45 af ec 72 ba 6f ff 60 75 25 6c 50 0e 1c bc "
                    "c6 c9 73 33 d4 b4 05 f6 2d 1d cd 95 29 95 a0 4f 8a cc 18 e6 "
                    "4d c9 53 e7 bd 60 2d 54 f0 c7 1f 25 b6 1b c6 b7 8c 4d 72 c4 "
                    "bb 1f 99 84 97 bd ac f0 80 a3 e3 88 67 11 a2 00 c6 2c 62 76 "
                    "2e 2f 37 86 d8 90 17 2d 2c d0 34 6e ca 4f 9f d5 59",
            [S2N_HASH_SHA1] =
                    "3c e9 9f a7 7a 37 c3 72 ab 08 03 c9 aa 3a 7b 41 12 a1 07 10 "
                    "35 9a 57 f6 60 c5 79 a8 2f ad cc 62 b6 13 f3 fe a3 1e 94 b1 "
                    "c9 11 d1 50 24 15 66 7c 02 9d 17 f2 99 84 3e 61 bd 56 9e 09 "
                    "6a e1 18 fa cd 78 8a 00 d9 9a 28 95 1f ee e1 01 89 6f c4 2b "
                    "44 06 0c 2f 0e f5 ba dc 55 3c 7b d4 10 20 74 1b 1d f6 e0 ba "
                    "29 7b c0 7c 9f ab 1a 79 aa 58 d6 01 2e 9c b0 5b 97 4e c7 45 "
                    "76 b6 45 dc 36 7d da 8b 5e 8a bf 2c 51 d0 23 1d f4 a9 12 11 "
                    "0e e3 e1 0d 2e 5f 92 19 10 48 54 18 d1 4e 61 ec e6 47 60 13 "
                    "65 eb 84 cf d8 b9 4b 99 37 99 ef 83 58 6c e7 fd c0 fc a2 35 "
                    "99 0f 26 48 24 5e 0a 21 42 e1 77 a7 50 a2 ec ae d8 2f f1 18 "
                    "44 31 b4 5a a7 c7 93 1e 60 e7 2e 8b 9a 22 4a ee d4 0e 8d eb "
                    "da 36 01 ae e3 1d 52 3f 33 fb 84 b8 f8 a4 1b 75 c5 ce 51 9f "
                    "d8 2b 56 e0 32 98 be c4 f3 24 f2 7a fa c6 72 21",
            [S2N_HASH_SHA224] =
                    "06 f6 e6 82 f2 79 98 a6 9a e0 5f 20 ad c7 eb 9f 41 0d 18 10 "
                    "86 9e d1 7f e4 b1 7d 39 e0 9f 05 4e 7a ce 7c c1 ba 29 c4 f4 "
                    "f0 e8 89 44 91 3f 65 8e 57 84 27 8e 88 9f 14 ee 04 fd 73 47 "
                    "40 03 fe 53 a6 c7 cd e0 db 27 9f 12 36 47 fc e7 7c 3f b9 f2 "
                    "f7 55 15 93 02 f9 5d a0 10 c7 13 cb d9 98 5c 22 d0 63 c7 5f "
                    "c0 8b 1a ac ec 2d 5d 2c 3e db 41 34 31 f3 0b c1 29 bc 83 a4 "
                    "27 37 61 17 5c 15 01 43 68 8f 3d 6e 23 76 f4 f1 a4 44 ce 5e "
                    "fc 61 88 85 5e d9 0e 2f 80 7e 56 ac 62 aa 2a a9 aa 46 8f da "
                    "ee f4 fe 1a 28 e8 78 25 fb b5 83 22 c9 d0 dd 28 f7 93 02 e5 "
                    "93 31 db 0f 9b 17 ae e2 a7 72 56 c8 53 ee 3a 80 c2 7c 15 3c "
                    "59 66 d5 c4 e3 99 9f cb f2 16 67 ac 9a 3a 03 b8 17 ce 77 12 "
                    "28 8a fd 21 ca 4c bf 06 b1 73 8e 6d 51 1c a3 d5 ec 82 66 ef "
                    "62 f3 9f 4a 22 c4 22 ed 13 a2 6d b8 96 5c b8 73",
            [S2N_HASH_SHA256] =
                    "05 25 f7 42 ee 12 e9 ca 45 05 7c 96 32 03 a5 50 04 46 06 a2 "
                    "a5 57 d3 69 00 4a bc c2 21 a3 e9 2c 11 56 97 16 92 54 ba f3 "
                    "3b a6 67 ae 7f e6 89 74 be e7 16 43 3c 66 a3 51 93 96 c6 13 "
                    "af 8a 46 fe a9 f5 00 d7 de d5 02 76 2a f5 80 52 1f 6f 4f d6 "
                    "b9 a7 ab 62 66 57 51 5c 77 6e 46 03 e2 ef c6 dc f2 da f2 fc "
                    "8c 2a 80 ec 3b 9a ac 64 2e 34 49 cd ac 3f bc a4 82 84 6e 6d "
                    "49 cd 94 1b e3 ad be 96 15 27 89 a5 8f f7 35 16 7f e5 71 fe "
                    "b7 4a 45 4d ca 44 c7 bc ed 91 9a c4 0f bf 75 53 22 51 df 84 "
                    "7f 7e 71 b8 ef 4f 1f e5 cb 19 a3 87 4f 32 8d e7 06 a9 3f 81 "
                    "b9 ff 3c 14 07 9a b6 cb fa 02 d8 51 16 9f 4c 2d 03 ac d5 c1 "
                    "7e 73 5a a4 c6 b9 d1 7d a2 1a 17 9c c4 c1 7c a2 77 18 e5 2b "
                    "41 9e ab e6 e9 46 03 6f 44 95 11 8f 5e 51 d6 0a f4 e6 04 30 "
                    "89 18 9f 16 25 91 1d 74 64 c4 23 5d b5 fc f9 47",
            [S2N_HASH_SHA384] =
                    "36 15 7c 11 a3 02 67 6d 40 8d 0f 7a c5 7e 2d 41 52 e6 16 "
                    "f2 4a 6b 60 a8 a7 0c 91 dc 5d a5 ed b4 98 98 24 be 05 d6 49 "
                    "aa 05 4f ba 54 5b 8d 21 e2 1f c5 1c 7e 99 52 f7 c9 19 fe a7 "
                    "e0 62 61 57 67 05 fa 15 1b a3 45 72 01 e0 0b e4 1f 69 1a 05 05"
                    "69 af f3 8a 4b 30 37 76 24 25 fd 55 c8 87 7b bc b7 b5 37 21 "
                    "dc f2 15 76 7e 68 11 ae 38 ce 2d e4 75 36 4a e1 f4 55 13 90 "
                    "70 8b db 1d 94 83 3b 88 83 48 bb 5e 0c 2e 23 f9 00 ed 59 a4 "
                    "c7 54 9e a0 0d 7d d3 72 7c e2 26 5c f8 34 34 eb 6a 85 f2 a3 "
                    "9a 47 8d c0 20 60 49 05 bb b7 6b 8b 52 f2 bc 35 11 da 97 f3 "
                    "4c 2d 93 29 ae 63 96 16 38 bc 8b a8 ba e7 d1 74 08 14 db f3 "
                    "51 a0 6f 87 4d 20 02 a7 db 0e 73 6a c1 55 75 26 61 34 5c 03 "
                    "f8 0c c0 a3 b6 ca 76 a7 68 61 84 53 58 f9 cf 11 67 29 04 8f "
                    "7b 24 a5 91 4b c2 b2 b2 21 81 f6 48 33 18 0c 7a",
            [S2N_HASH_SHA512] =
                    "53 73 1c 33 80 1a 25 76 4c 0f 91 d6 7e 41 58 03 c9 71 56 "
                    "ef 54 06 19 05 37 99 57 10 63 91 a3 5b 83 85 dd 65 09 42 af "
                    "b7 51 45 83 e2 b9 ca 23 4c 92 eb 85 35 d0 23 c1 02 62 c5 46 "
                    "24 95 75 be 3c 1d e4 6c 45 87 a9 7a f3 c7 32 81 09 22 b2 c3 "
                    "43 d0 02 22 04 93 08 89 de 07 0a bb d2 68 25 06 6a 95 13 07 2d "
                    "74 4a 2c 37 a8 0d 74 e3 b5 b8 e2 8e ad 4d 7a 94 11 c7 4b 90 "
                    "0c 66 ec 4b 21 cd 2b b7 ae 68 32 01 0b 4c 93 6a 8f 7f a4 e6 "
                    "d1 7b a4 48 ef 6a 5e 29 c9 2b 20 51 6b 39 22 17 15 40 ef 7e "
                    "49 87 75 77 92 ed 4e af ae 92 b0 e5 10 47 ea b1 e9 8d 05 23 "
                    "dc 99 f1 b8 94 22 96 f4 02 6e 9a 35 57 8e 85 08 ee 03 7c 5e "
                    "df 2c 3f 49 22 bd 04 50 ff e9 48 eb 96 7a ee 80 51 e2 ab 94 "
                    "6d c8 73 73 3b 5e 65 f7 c7 49 de a8 3b 91 e1 5f 25 63 13 e0 "
                    "e9 51 79 99 54 0d 1a 1f 91 d3 41 e1 a3 b3 05 05",
        };

        DEFER_CLEANUP(struct s2n_pkey public_key_parsed = { 0 }, s2n_pkey_free);
        EXPECT_OK(s2n_setup_public_key(&public_key_parsed, rsa_cert_chain));

        struct s2n_pkey *private_key = rsa_cert_chain->private_key;
        struct s2n_pkey *public_key = &public_key_parsed;
        EXPECT_PKEY_USES_EVP_SIGNING(private_key);
        EXPECT_PKEY_USES_EVP_SIGNING(public_key);

        for (size_t i = 0; i < all_sig_schemes->count; i++) {
            const struct s2n_signature_scheme *scheme = all_sig_schemes->signature_schemes[i];
            if (scheme->sig_alg != sig_alg) {
                continue;
            }
            const s2n_hash_algorithm hash_alg = scheme->hash_alg;

            /* Test that EVP can sign and verify */
            s2n_stack_blob(evp_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
            EXPECT_OK(s2n_test_evp_sign(sig_alg, hash_alg, private_key, &evp_signature));
            EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &evp_signature));

            /* Test known value matches sign: RSA PKCS1 is deterministic */
            S2N_BLOB_FROM_HEX(known_value, valid_signatures[hash_alg]);
            EXPECT_EQUAL(known_value.size, evp_signature.size);
            EXPECT_BYTEARRAY_EQUAL(known_value.data, evp_signature.data, evp_signature.size);
            /* Test verifying known value */
            EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &known_value));

            /* Verify using legacy methods */
            if (s2n_test_legacy_signing_supported()) {
                DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
                EXPECT_SUCCESS(s2n_hash_new(&hash_state));

                s2n_stack_blob(rsa_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
                EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
                EXPECT_SUCCESS(s2n_rsa_pkcs1v15_sign(private_key, &hash_state, &rsa_signature));

                /* EVP verifies legacy signature */
                EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &rsa_signature));

                /* legacy verifies EVP signature */
                EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
                EXPECT_SUCCESS(s2n_rsa_pkcs1v15_verify(public_key, &hash_state, &evp_signature));
            }
        }
    };

    /* EVP signing must match ECDSA signing */
    {
        s2n_signature_algorithm sig_alg = S2N_SIGNATURE_ECDSA;

        const char *valid_signatures[S2N_HASH_ALGS_COUNT] = {
            [S2N_HASH_SHA1] =
                    "30 65 02 30 2f d6 a0 48 6b 17 9a e9 d6 c3 ad 16 db a4 04 "
                    "27 d3 c8 84 63 67 2b 07 b3 df 98 d7 f2 88 58 d1 9a 45 0d e7 "
                    "f7 f6 c8 ef 83 76 a2 23 24 60 3e a3 81 02 31 00 a4 9f f2 d2 "
                    "34 d8 96 40 02 73 3b 08 91 17 76 67 6f ce d4 00 83 87 1e 4e "
                    "9e 88 a9 3a 1b f0 06 f6 39 f8 ac a5 0d da 27 b8 89 bd be a6 "
                    "58 ce a5 b6",
            [S2N_HASH_SHA224] =
                    "30 65 02 31 00 ac 40 4c e0 c6 96 d2 00 c3 a0 d2 d0 21 6a 87 "
                    "75 60 8a 95 47 e5 81 d3 9e d0 ba 1a be 57 49 15 1a df 8f c7 "
                    "be 21 84 49 4b a6 1c 22 cb 89 e3 57 14 02 30 52 c4 ea bf c1 "
                    "05 d9 a8 76 73 70 8c 2a d2 de 68 df 73 80 5d 89 13 ff c4 b9 "
                    "4e eb fc fc cf 4c 2e 9c 90 d8 85 ad 6c bb 13 86 63 04 ff 58 "
                    "d0 1a 34",
            [S2N_HASH_SHA256] =
                    "30 66 02 31 00 eb 65 34 a1 7e de 30 11 fd a7 8f ba 41 5f "
                    "3b 72 88 23 ae fa 41 14 05 3c ee ef d7 2c fa 4f 51 0d 66 63 "
                    "4f b2 a4 34 6c 1b 28 69 96 eb b5 5f 13 1b 02 31 00 88 7b ed "
                    "90 f6 ab d7 4b b8 60 ef 60 50 19 2e 65 f8 e9 20 a8 23 10 ac "
                    "45 81 37 fb 8b 0c f2 10 d1 18 d1 46 62 15 06 06 8c bb a7 6b "
                    "e5 29 d2 26 d4",
            [S2N_HASH_SHA384] =
                    "30 64 02 30 76 f2 dc 15 27 47 b5 d2 12 6e 97 ca 48 27 89 "
                    "13 f4 ea 34 1b 6c cd e7 ef 8a 56 15 0a 87 7d 55 d7 74 08 61 "
                    "78 04 1c 27 6d 55 81 32 90 9d 31 8f 35 02 30 46 c6 88 8a 2f "
                    "b1 d9 a1 db cd 52 d3 fc c2 e4 cd 62 ec 42 28 e5 e3 58 9c b0 "
                    "02 cd e5 60 39 53 7c 86 e6 17 ad 03 16 50 75 cc a1 22 61 04 "
                    "a0 30 19",
            [S2N_HASH_SHA512] =
                    "30 65 02 30 7c 40 b3 ba a7 4c 0b 81 02 97 0c ff 3e 66 53 69 "
                    "86 83 e0 83 a0 14 f8 77 d1 1b 61 32 3e a2 c7 04 d3 cd b2 8c "
                    "92 b5 3c 01 a9 21 c3 8b 8d e2 e3 f6 02 31 00 c0 ea c3 b3 65 "
                    "ed ed fb cc 94 bb e7 db 44 93 e4 59 88 f2 d0 2c 8b 1e a7 70 "
                    "fe cf 12 dd 84 3d 70 79 05 8c 53 de a6 94 e0 e6 fa ef 35 75 "
                    "d8 11 11",
        };

        struct s2n_cert_chain_and_key *ecdsa_cert_chain = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_cert_chain,
                S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));
        DEFER_CLEANUP(struct s2n_pkey public_key_parsed = { 0 }, s2n_pkey_free);
        EXPECT_OK(s2n_setup_public_key(&public_key_parsed, ecdsa_cert_chain));

        struct s2n_pkey *private_key = ecdsa_cert_chain->private_key;
        struct s2n_pkey *public_key = &public_key_parsed;
        EXPECT_PKEY_USES_EVP_SIGNING(private_key);
        EXPECT_PKEY_USES_EVP_SIGNING(public_key);

        for (size_t i = 0; i < all_sig_schemes->count; i++) {
            const struct s2n_signature_scheme *scheme = all_sig_schemes->signature_schemes[i];
            if (scheme->sig_alg != sig_alg) {
                continue;
            }
            const s2n_hash_algorithm hash_alg = scheme->hash_alg;

            /* Test that EVP can sign and verify */
            s2n_stack_blob(evp_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
            EXPECT_OK(s2n_test_evp_sign(sig_alg, hash_alg, private_key, &evp_signature));
            EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &evp_signature));

            /* Test verifying known value */
            S2N_BLOB_FROM_HEX(known_value, valid_signatures[hash_alg]);
            EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &known_value));

            /* Verify using legacy methods */
            if (s2n_test_legacy_signing_supported()) {
                DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
                EXPECT_SUCCESS(s2n_hash_new(&hash_state));

                s2n_stack_blob(ecdsa_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
                EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
                EXPECT_SUCCESS(s2n_ecdsa_sign(private_key, sig_alg, &hash_state, &ecdsa_signature));

                /* EVP verifies legacy signature */
                EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &ecdsa_signature));

                /* legacy verifies EVP signature */
                EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
                EXPECT_SUCCESS(s2n_ecdsa_verify(public_key, sig_alg, &hash_state, &evp_signature));
            }
        }

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert_chain));
    };

    /* EVP signing must match RSA-PSS-RSAE signing */
    if (s2n_is_rsa_pss_signing_supported()) {
        s2n_signature_algorithm sig_alg = S2N_SIGNATURE_RSA_PSS_RSAE;

        const char *valid_signatures[S2N_HASH_ALGS_COUNT] = {
            [S2N_HASH_SHA256] =
                    "37 bd 68 e1 57 96 67 a4 c9 b8 cf 02 e6 f4 96 ab 65 9c bd "
                    "e2 33 2c f4 9b 66 03 f3 a6 2e ba 09 30 3b d0 d4 cf 5f 03 43 "
                    "50 56 55 b6 6c f2 f2 c4 e3 9a ea 9c 0d e4 8c 37 10 fe b9 1f "
                    "95 3f c8 fb 19 1d f4 bc 85 56 de 4e 1f 3f ff 21 f3 84 67 99 "
                    "4d 6f 21 74 6e f6 7d e0 40 3e e2 2a ad 76 c0 99 2d 22 35 2e "
                    "cc 18 c3 5a ef 39 8f 0e 86 17 55 5b fa a8 92 28 e4 16 28 0d "
                    "3b 84 2b 73 34 d3 97 b8 b0 ce 49 00 8d dd 36 4c 28 52 12 e4 "
                    "43 00 9b 42 f9 75 e3 79 65 ef 8b 42 d4 0d 22 78 58 76 b4 23 "
                    "4a c1 a2 8f 00 cb fd 82 71 71 f1 69 b2 1f c2 17 8b b0 06 06 "
                    "4b 19 a4 46 d5 54 88 6b 2d ce 69 79 cf 2f 81 59 ac d2 9a b7 "
                    "6b 7b 20 0e a2 9f 39 6d 8a dd 75 5a ef 5a 8f 2a 1c ac 0c 60 "
                    "d5 20 47 39 9d 79 83 cf 37 19 f5 56 62 02 09 ab 72 9c 0f 1e "
                    "ca 77 e6 c2 38 a4 b8 34 96 0f 2e bd e0 31 71 9d c5",
            [S2N_HASH_SHA384] =
                    "a3 40 0b e9 8f 93 77 50 d5 6d f2 34 7d 92 cf e2 e8 a1 6c "
                    "36 4d a1 70 92 de 4f 3e 2a 6f 25 e6 ae 47 3c ec f1 d2 10 20 "
                    "d2 e5 78 43 40 75 b9 2c 7f 0c 2e 95 26 e0 9d b4 e5 c8 d4 d4 "
                    "c0 b2 a9 a0 4b 83 a5 45 b2 f3 62 aa bb 17 b5 b1 ac c1 19 db "
                    "22 a0 49 86 3c 77 ae 13 5f eb b9 f2 2f 4e 57 4e 0f 1d 2a d9 "
                    "d3 d0 39 ac 61 fe f4 b9 85 20 ed 4c ff 34 f1 67 cd 21 60 a1 "
                    "fc 9c c2 b0 ec d2 43 38 7b 06 aa d9 e3 81 a3 73 88 6e c0 72 "
                    "e3 a4 6e 41 79 c2 b0 54 5a 42 fb c7 00 1e 4c a8 3e a3 41 17 "
                    "a6 67 b3 e0 dd 2f f1 2d dc 42 46 c7 74 47 15 7a 9b ad b6 b0 "
                    "cf d6 1e b3 14 4a b6 2b ab ad 9e db 86 6c 6f 37 c7 62 59 52 "
                    "bc 4f 2f 30 a3 41 17 c6 85 64 db d7 06 31 4f dc 7f 33 3a 3a "
                    "3e 4e 23 37 89 53 8d f1 fe 46 d6 cc 80 f4 ed c8 87 24 60 a7 "
                    "a5 92 77 67 3c 0b f7 fa 56 e1 ad f7 c5 82 9f 83 25",
            [S2N_HASH_SHA512] =
                    "95 63 f0 49 3e 93 f7 8c 76 f0 bf 0a 87 4d 2a 8b f7 45 b1 "
                    "c1 41 a4 d9 5f f1 43 cb 10 bc af 55 44 7d 61 78 75 f9 6a 98 "
                    "10 ef 3c ae f9 e0 f3 ce 5c 51 79 70 3e a9 cd 86 fc c8 a2 73 "
                    "21 60 f4 37 73 20 b7 a7 24 e3 ec 49 d9 e0 bd 20 7f d0 36 3c "
                    "dd 1f 36 a7 56 ee bf c9 c8 16 17 ef 07 48 ad b2 f1 dd 8d 65 "
                    "19 ec c4 b0 4d 94 80 9c 2e cc a6 a5 36 23 ed 1f 69 29 0e d9 "
                    "1b 72 ec 73 9d 5d 9b ec a5 c7 ec 24 86 ca 5f bc 70 92 b1 c3 "
                    "00 2d 15 4b 74 bb aa f9 c9 ca 60 77 2f 3a 59 b6 89 44 32 5c "
                    "8d bd 02 ed a1 b9 80 a7 17 bb b2 cc 89 a2 60 74 f0 20 d7 4d "
                    "a9 92 33 90 2c 7c ab ec f6 a3 38 22 32 e5 83 b6 09 14 b5 b4 "
                    "3b 23 25 92 33 16 5e 40 8b b2 97 89 e9 82 d6 10 0b 2c b7 f0 "
                    "81 81 c4 00 b3 38 84 bc 39 00 e2 6d 38 f0 e7 1b 66 ad 62 06 "
                    "1b 76 62 18 3c 2a d9 b6 a8 fd af b4 1f a4 92 e9 24",
        };

        DEFER_CLEANUP(struct s2n_pkey public_key_parsed = { 0 }, s2n_pkey_free);
        EXPECT_OK(s2n_setup_public_key(&public_key_parsed, rsa_cert_chain));

        struct s2n_pkey *private_key = rsa_cert_chain->private_key;
        struct s2n_pkey *public_key = &public_key_parsed;
        EXPECT_PKEY_USES_EVP_SIGNING(private_key);
        EXPECT_PKEY_USES_EVP_SIGNING(public_key);

        for (size_t i = 0; i < all_sig_schemes->count; i++) {
            const struct s2n_signature_scheme *scheme = all_sig_schemes->signature_schemes[i];
            if (scheme->sig_alg != sig_alg) {
                continue;
            }
            const s2n_hash_algorithm hash_alg = scheme->hash_alg;

            /* Test that EVP can sign and verify */
            s2n_stack_blob(evp_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
            EXPECT_OK(s2n_test_evp_sign(sig_alg, hash_alg, private_key, &evp_signature));
            EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &evp_signature));

            /* Test verifying known value */
            S2N_BLOB_FROM_HEX(known_value, valid_signatures[hash_alg]);
            EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &known_value));

            /* Verify using legacy methods */
            if (s2n_test_legacy_signing_supported()) {
                DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
                EXPECT_SUCCESS(s2n_hash_new(&hash_state));

                s2n_stack_blob(rsa_pss_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
                EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
                EXPECT_SUCCESS(s2n_rsa_pss_sign(private_key, &hash_state, &rsa_pss_signature));

                /* EVP verifies legacy signature */
                EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &rsa_pss_signature));

                /* legacy verifies EVP signature */
                EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
                EXPECT_SUCCESS(s2n_rsa_pss_verify(public_key, &hash_state, &evp_signature));
            }
        }
    }

    /* EVP signing must match RSA-PSS-PSS signing */
    if (s2n_is_rsa_pss_certs_supported()) {
        s2n_signature_algorithm sig_alg = S2N_SIGNATURE_RSA_PSS_PSS;

        const char *valid_signatures[S2N_HASH_ALGS_COUNT] = {
            [S2N_HASH_SHA256] =
                    "66 0c 25 38 fd a1 bc b8 ca 48 3f 3d b9 3f 55 49 f6 3b 8c "
                    "62 95 60 74 bd 5d 53 bb 57 64 3a 63 63 04 04 fb e4 cf 15 82 "
                    "11 13 7c e0 ab 66 b2 c9 44 67 db b3 f2 55 24 32 31 29 d9 f7 "
                    "d4 be 53 02 75 bd e1 3d 27 6d 45 74 65 9e 20 27 96 ba 09 32 "
                    "81 8c 0e bb 7f 4b 7f e4 0a 95 22 68 a8 48 8a 8d 32 13 2e c0 "
                    "12 74 88 0e 48 74 99 c4 7b 6a 0e 62 0a c6 cb 04 87 f2 9b dc 9e "
                    "d7 e5 28 34 9a 75 bc 55 fa c4 71 20 17 4d 11 31 00 f5 cd 5e "
                    "13 65 74 b5 e8 5a a2 16 d5 22 84 3c 3f f0 96 2c b4 32 bc 9a "
                    "9a d0 02 4e e1 ac f3 ad 6b 9e 4f 99 90 19 6a cf 46 9f 04 5c "
                    "ba 0c f4 4e 06 2d 67 29 f5 88 63 c9 2f 3a 69 4c 36 8e 2c 64 "
                    "1d e6 b4 97 cb fc e2 c7 ae 6e c7 57 74 c6 ad a8 79 15 2f 5a "
                    "9d 18 4a 64 e9 5c f2 dc 9c 4b 9f 07 70 9c be e9 7a 20 18 2c "
                    "4b ca ab 27 47 cb ec 1a b0 88 b7 ea a7 e6 85 68",
            [S2N_HASH_SHA384] =
                    "28 4d cd 9f 75 79 a9 fe 08 77 df 73 98 8e 70 6b 73 6e db "
                    "d6 eb a0 0e a4 53 31 53 79 7b af 94 eb 1e 6e b8 66 76 b6 34 "
                    "f4 8c 78 f0 57 d4 3b 48 45 24 e7 55 52 16 89 f9 78 06 25 9c "
                    "98 0b b3 da 20 20 c8 e2 41 24 fd a2 7f ac 73 0b 04 90 c3 77 "
                    "65 37 3a b6 73 cd 9b 4b 14 2e f5 53 f9 c1 7d 5d fd 0c 9d 02 "
                    "96 7f bd 1d 7f fa eb 0c e3 0a 65 29 5c 96 09 2f 11 4c 1d 03 b2 "
                    "18 6e 7c b8 e3 0d 03 f8 df ad 65 08 83 57 bb 71 5b 2b 98 03 47 "
                    "fc d2 d7 db 4b e3 9b 2b b4 37 a6 db db 8b 8d 67 ca 1a fe bd "
                    "f1 d3 f9 53 8f 78 ba 4a e0 55 b4 c6 37 de e5 41 e4 e0 2f 28 "
                    "83 ce b6 8b 5b 68 9b a3 75 fd 5c 61 ab d3 3c a4 4e 69 89 4a "
                    "bd 74 84 78 6e 89 00 66 b8 2d 5b 98 ff ce 61 f2 59 80 56 34 "
                    "aa 66 1f 75 df 10 20 80 4a cb 1c 9b 41 d0 c2 9b a1 9b 68 f0 "
                    "7c 10 73 0f 81 e7 f6 6a 6e 27 70 5e ff a9 bd",
            [S2N_HASH_SHA512] =
                    "5a 9b 32 6f aa 20 e2 a7 0b ec 7f 00 17 24 04 dc 7f 6f 17 02 "
                    "db 82 dc 18 7f d8 2c b7 a9 8e 05 ae 84 c6 4a 87 2b 8b 14 f4 "
                    "54 59 83 4c d4 80 64 5a 54 bb 23 c6 ad 8a f8 70 31 18 96 99 "
                    "5f a9 49 98 70 55 a6 18 9b 0a d8 03 9b 3e 68 19 72 34 41 c4 "
                    "bb 99 f1 a3 3d 9e 5d 7e 79 4b 74 a0 72 fc cb 83 5b 16 38 17 "
                    "e0 0e 57 55 4c d3 3a 9e de 8e d5 5f d5 be 5e 6d 85 91 fa fa "
                    "44 90 b7 d3 cb b1 65 12 98 e8 6f d2 f3 6c 80 ef 3e dc 2b 42 "
                    "71 a1 73 55 db 44 7d e5 2f 2b be a8 73 15 72 2b 72 df fb ed "
                    "c1 39 34 2f bb 9d c9 be 97 25 3c e0 ae e6 af 2c 06 d3 5e e5 "
                    "65 a9 1c 22 6b 5d fa bb c7 78 af 70 34 e0 f1 80 b8 f4 b1 17 "
                    "94 f3 ea b6 7c f4 be b8 ec 05 29 f1 d1 e4 f7 91 aa 47 2e f3 "
                    "b0 0b 61 78 77 37 5f 47 86 7b c7 c8 59 25 a6 e1 91 14 d0 31 "
                    "b9 cd 6a 52 85 7b 06 01 40 f1 d2 5a d0 6a 3d f7",
        };

        struct s2n_cert_chain_and_key *rsa_pss_cert_chain = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_pss_cert_chain,
                S2N_RSA_PSS_2048_SHA256_LEAF_CERT, S2N_RSA_PSS_2048_SHA256_LEAF_KEY));
        DEFER_CLEANUP(struct s2n_pkey public_key_parsed = { 0 }, s2n_pkey_free);
        EXPECT_OK(s2n_setup_public_key(&public_key_parsed, rsa_pss_cert_chain));

        struct s2n_pkey *private_key = rsa_pss_cert_chain->private_key;
        struct s2n_pkey *public_key = &public_key_parsed;
        EXPECT_PKEY_USES_EVP_SIGNING(private_key);
        EXPECT_PKEY_USES_EVP_SIGNING(public_key);

        for (size_t i = 0; i < all_sig_schemes->count; i++) {
            const struct s2n_signature_scheme *scheme = all_sig_schemes->signature_schemes[i];
            if (scheme->sig_alg != sig_alg) {
                continue;
            }
            const s2n_hash_algorithm hash_alg = scheme->hash_alg;

            /* Test that EVP can sign and verify */
            s2n_stack_blob(evp_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
            EXPECT_OK(s2n_test_evp_sign(sig_alg, hash_alg, private_key, &evp_signature));
            EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &evp_signature));

            /* Test verifying known value */
            S2N_BLOB_FROM_HEX(known_value, valid_signatures[hash_alg]);
            EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &known_value));

            /* Verify using legacy methods */
            if (s2n_test_legacy_signing_supported()) {
                DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
                EXPECT_SUCCESS(s2n_hash_new(&hash_state));

                s2n_stack_blob(rsa_pss_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
                EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
                EXPECT_SUCCESS(s2n_rsa_pss_sign(private_key, &hash_state, &rsa_pss_signature));

                /* EVP verifies legacy signature */
                EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &rsa_pss_signature));

                /* legacy verifies EVP signature */
                EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
                EXPECT_SUCCESS(s2n_rsa_pss_verify(public_key, &hash_state, &evp_signature));
            }
        }

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_pss_cert_chain));
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_cert_chain));
    END_TEST();
}
