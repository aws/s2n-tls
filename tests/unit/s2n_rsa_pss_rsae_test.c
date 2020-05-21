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

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#include "crypto/s2n_hash.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_rsa_pss.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"
#include "utils/s2n_random.h"

#define HASH_ALG S2N_HASH_SHA256
#define HASH_LENGTH 256
#define RANDOM_BLOB_SIZE RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE

#define hash_state_new(name, input) \
    DEFER_CLEANUP(struct s2n_hash_state name = {0}, s2n_hash_free); \
    EXPECT_SUCCESS(s2n_hash_new(&name)); \
    EXPECT_SUCCESS(s2n_hash_init(&name, HASH_ALG)); \
    EXPECT_SUCCESS(s2n_hash_update(&name, (input).data, (input).size)); \

#define hash_state_for_alg_new(name, hash_alg, input) \
    DEFER_CLEANUP(struct s2n_hash_state name = {0}, s2n_hash_free); \
    EXPECT_SUCCESS(s2n_hash_new(&name)); \
    EXPECT_SUCCESS(s2n_hash_init(&name, hash_alg)); \
    EXPECT_SUCCESS(s2n_hash_update(&name, (input).data, (input).size)); \

struct test_case {
    s2n_hash_algorithm hash_alg;
    const char* message;
    const char* expected_signature;
};

/* Small selection of NIST test vectors, taken from:
 * https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Digital-Signatures */

const struct test_case test_cases[] = {
        { .hash_alg = S2N_HASH_SHA224,
          .message = "6f2841166a64471d4f0b8ed0dbb7db32161da13b2b90757b77c7c201"
                "e0dfbe7b68a39c9f010c04c9a404c0e59d6fb88f296c207942d8f00dba159"
                "4548709e5175e69594483377692df898d68538da4fc4ccab4b897a815e177"
                "33367af51c91667800dece95ed87c228235d23a41789c0a7bec5bfd207cc3"
                "fd7aa0e3bd320a9b1",
          .expected_signature = "15f9616eed464777655b7b6a00fc8e3d186d60a143a84"
                  "11d891539b886232bc4cc9e0d71ff8df4828b32ea9afecca3adc57c2ac6"
                  "d355444201d2ad5a1385ae403e2faebac111b0c3f63a0bf7bba927f537f"
                  "a301ced57e274834d62c6e4d054035f777eb7db6a97be389695d1785f9a"
                  "9aa02d8d3680dd911bc1bf83d310cc8a8d"
        },

        { .hash_alg = S2N_HASH_SHA256,
          .message = "5e611473dd3cb92238300ed54abd603662041b92e9dc8d8d4523ec15"
                  "fc529b941d54a96adc999b9a7c666bc3726fd053c7a7c0f7be573356b76"
                  "d2bfe5317f19ed991a177d83ce80d0eef0d2289912ee40ce8cd66b4ac8b"
                  "4ddbe032cc3d62f9d259c004811b4d2be3b774fcd8d84d0353fa6e49c61"
                  "4041adb7b220b6503583c96",
          .expected_signature = "b32cb5cba065259681b9b91eb44345fb89d281d1d77e7"
                  "6eacfae05b1a2bf988b97a1b751c169168c58d73610599a6f856f656ec4"
                  "c7095f9d7c5c87eddf046bd5eae0298c73e1b360e133dc0d4006259d6ce"
                  "f6aff26832c086ded86ca0a7b5f7f36b607a4eb8ebbe2619a74647faa9e"
                  "e38352006c41e7e6414a5240a728949e63",
        },

        { .hash_alg = S2N_HASH_SHA384,
          .message = "e511903c2f1bfba245467295ac95413ac4746c984c3750a728c388aa"
                  "628b0ebf70bfa2b5b5bf701d4ad6eda4fd2502a09add6ce86ab263e9fa8"
                  "c79f61d7fc6e034fd42c7ad4a722fca314756a4f643c66f8bdd26ff0627"
                  "558b53aebab226a1d5bb34361a21a34a004fbf4855a8ee4bd4cae687f91"
                  "41de5146681ed9d276ae9c7",
          .expected_signature = "9c748702bbcc1f9468864cd360c8c39d007b2d8aaee83"
                  "3606c70f7593cf0d151924eac33d36b6b815019fa0575a518de4ea8ce8a"
                  "3a8e31c4242d3471b30bc198dab341bea977eccc4f69b8fb4ba21b0b90b"
                  "fc0478f2e34b32006eb7bf915f72da247e13cdc6d00ffe38c2853030c83"
                  "2e4c065f8ac3350ef403a8953f951e0832",
        },
};

const char* kye_param_n = "bcb47b2e0dafcba81ff2a2b5cb115ca7e757184c9d72bcdc"
        "da707a146b3b4e29989ddc660bd694865b932b71ca24a335cf4d339c719183e6222e4c"
        "9ea6875acd528a49ba21863fe08147c3a47e41990b51a03f77d22137f8d74c43a5a45f"
        "4e9e18a2d15db051dc89385db9cf8374b63a8cc88113710e6d8179075b7dc79ee76b";

const char* key_param_e = "0000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000010001";

const char* key_param_d = "383a6f19e1ea27fd08c7fbc3bfa684bd6329888c0bbe4c98625e"
        "7181f411cfd0853144a3039404dda41bce2e31d588ec57c0e148146f0fa65b39008ba5"
        "835f829ba35ae2f155d61b8a12581b99c927fd2f22252c5e73cba4a610db3973e019ee"
        "0f95130d4319ed413432f2e5e20d5215cdd27c2164206b3f80edee51938a25c1";

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Load the RSA cert */
    struct s2n_cert_chain_and_key *rsa_cert_chain;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_cert_chain,
            S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY));

    s2n_stack_blob(result, HASH_LENGTH, HASH_LENGTH);

    /* Generate a random blob of data */
    s2n_stack_blob(random_msg, RANDOM_BLOB_SIZE, RANDOM_BLOB_SIZE);
    EXPECT_OK(s2n_get_private_random_data(&random_msg));

    /* If RSA_PSS not supported, cannot sign/verify with PSS */
    {
        struct s2n_pkey rsa_public_key;
        s2n_pkey_type rsa_pkey_type;
        EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&rsa_public_key, &rsa_pkey_type, &rsa_cert_chain->cert_chain->head->raw));
        EXPECT_EQUAL(rsa_pkey_type, S2N_PKEY_TYPE_RSA);

        hash_state_new(sign_hash, random_msg);
        hash_state_new(verify_hash, random_msg);

        EXPECT_EQUAL(s2n_is_rsa_pss_signing_supported(), RSA_PSS_SIGNING_SUPPORTED);

        if (!s2n_is_rsa_pss_signing_supported()) {
            EXPECT_FAILURE_WITH_ERRNO(rsa_public_key.sign(rsa_cert_chain->private_key, S2N_SIGNATURE_RSA_PSS_RSAE, &sign_hash, &result),
                    S2N_RSA_PSS_NOT_SUPPORTED);
            EXPECT_FAILURE_WITH_ERRNO(rsa_public_key.verify(&rsa_public_key, S2N_SIGNATURE_RSA_PSS_RSAE, &verify_hash, &result),
                    S2N_RSA_PSS_NOT_SUPPORTED);
        } else {
            EXPECT_SUCCESS(rsa_public_key.sign(rsa_cert_chain->private_key, S2N_SIGNATURE_RSA_PSS_RSAE, &sign_hash, &result));
            EXPECT_SUCCESS(rsa_public_key.verify(&rsa_public_key, S2N_SIGNATURE_RSA_PSS_RSAE, &verify_hash, &result));
        }

        EXPECT_SUCCESS(s2n_pkey_free(&rsa_public_key));
    }

    #if RSA_PSS_CERTS_SUPPORTED

    struct s2n_cert_chain_and_key *rsa_pss_cert_chain;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_pss_cert_chain,
            S2N_RSA_PSS_2048_SHA256_LEAF_CERT, S2N_RSA_PSS_2048_SHA256_LEAF_KEY));

    /* Self-Talk tests */
    {
        struct s2n_pkey rsa_public_key;
        s2n_pkey_type rsa_pkey_type;
        EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&rsa_public_key, &rsa_pkey_type, &rsa_cert_chain->cert_chain->head->raw));
        EXPECT_EQUAL(rsa_pkey_type, S2N_PKEY_TYPE_RSA);

        /* Test: RSA cert can sign/verify with PSS */
        {
            hash_state_new(sign_hash, random_msg);
            hash_state_new(verify_hash, random_msg);

            EXPECT_SUCCESS(rsa_public_key.sign(rsa_cert_chain->private_key, S2N_SIGNATURE_RSA_PSS_RSAE, &sign_hash, &result));
            EXPECT_SUCCESS(rsa_public_key.verify(&rsa_public_key, S2N_SIGNATURE_RSA_PSS_RSAE, &verify_hash, &result));
        }

        /* Test: RSA cert can't verify with PSS what it signed with PKCS1v1.5 */
        {
            hash_state_new(sign_hash, random_msg);
            hash_state_new(verify_hash, random_msg);

            EXPECT_SUCCESS(rsa_public_key.sign(rsa_cert_chain->private_key, S2N_SIGNATURE_RSA_PSS_RSAE, &sign_hash, &result));
            EXPECT_FAILURE_WITH_ERRNO(rsa_public_key.verify(&rsa_public_key, S2N_SIGNATURE_RSA, &verify_hash, &result),
                    S2N_ERR_VERIFY_SIGNATURE);
        }

        /* Test: RSA cert can't verify with PKCS1v1.5 what it signed with PSS */
        {
            hash_state_new(sign_hash, random_msg);
            hash_state_new(verify_hash, random_msg);

            EXPECT_SUCCESS(rsa_public_key.sign(rsa_cert_chain->private_key, S2N_SIGNATURE_RSA, &sign_hash, &result));
            EXPECT_FAILURE_WITH_ERRNO(rsa_public_key.verify(&rsa_public_key, S2N_SIGNATURE_RSA_PSS_RSAE, &verify_hash, &result),
                    S2N_ERR_VERIFY_SIGNATURE);
        }

        /* Test: If they share the same RSA key,
         * an RSA cert and an RSA_PSS cert are equivalent for PSS signatures. */
        {
            struct s2n_pkey rsa_pss_public_key;
            s2n_pkey_type rsa_pss_pkey_type;
            EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&rsa_pss_public_key, &rsa_pss_pkey_type, &rsa_pss_cert_chain->cert_chain->head->raw));
            EXPECT_EQUAL(rsa_pss_pkey_type, S2N_PKEY_TYPE_RSA_PSS);

            /* Set the keys equal */
            const BIGNUM *n, *e, *d;
            RSA_get0_key(EVP_PKEY_get0_RSA(rsa_public_key.pkey), &n, &e, &d);
            EXPECT_SUCCESS(RSA_set0_key(EVP_PKEY_get0_RSA(rsa_pss_public_key.pkey),
                    BN_dup(n), BN_dup(e), BN_dup(d)));

            /* RSA signed with PSS, RSA_PSS verified with PSS */
            {
                hash_state_new(sign_hash, random_msg);
                hash_state_new(verify_hash, random_msg);

                EXPECT_SUCCESS(rsa_public_key.sign(rsa_cert_chain->private_key, S2N_SIGNATURE_RSA_PSS_RSAE, &sign_hash, &result));
                EXPECT_SUCCESS(rsa_pss_public_key.verify(&rsa_public_key, S2N_SIGNATURE_RSA_PSS_PSS, &verify_hash, &result));
            }

            /* RSA_PSS signed with PSS, RSA verified with PSS */
            {
                hash_state_new(sign_hash, random_msg);
                hash_state_new(verify_hash, random_msg);

                EXPECT_SUCCESS(rsa_pss_public_key.sign(rsa_cert_chain->private_key, S2N_SIGNATURE_RSA_PSS_PSS, &sign_hash, &result));
                EXPECT_SUCCESS(rsa_public_key.verify(&rsa_public_key, S2N_SIGNATURE_RSA_PSS_RSAE, &verify_hash, &result));
            }

            EXPECT_SUCCESS(s2n_pkey_free(&rsa_pss_public_key));
        }

        EXPECT_SUCCESS(s2n_pkey_free(&rsa_public_key));
    }

    /* Test: NIST test vectors */
    {
        struct s2n_pkey rsa_public_key;
        s2n_pkey_type rsa_pkey_type;
        EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&rsa_public_key, &rsa_pkey_type, &rsa_cert_chain->cert_chain->head->raw));
        EXPECT_EQUAL(rsa_pkey_type, S2N_PKEY_TYPE_RSA);

        RSA *rsa_key = EVP_PKEY_get0_RSA(rsa_public_key.pkey);
        BIGNUM *n, *e, *d;
        n = BN_new(); e = BN_new(); d = BN_new();
        EXPECT_SUCCESS(BN_hex2bn(&n, kye_param_n));
        EXPECT_SUCCESS(BN_hex2bn(&e, key_param_e));
        EXPECT_SUCCESS(BN_hex2bn(&d, key_param_d));
        EXPECT_SUCCESS(RSA_set0_key(rsa_key, n, e, d));

        struct s2n_stuffer message_stuffer, signature_stuffer;
        struct s2n_stuffer input_stuffer;

        for (int i = 0; i < sizeof(test_cases) / sizeof(struct test_case); i++) {
            s2n_stuffer_alloc_ro_from_hex_string(&message_stuffer, test_cases[i].message);
            s2n_stuffer_alloc_ro_from_hex_string(&signature_stuffer, test_cases[i].expected_signature);

            hash_state_for_alg_new(verify_hash, test_cases[i].hash_alg, message_stuffer.blob);

            EXPECT_SUCCESS(rsa_public_key.verify(&rsa_public_key, S2N_SIGNATURE_RSA_PSS_RSAE, &verify_hash, &signature_stuffer.blob));

            s2n_stuffer_free(&message_stuffer);
            s2n_stuffer_free(&signature_stuffer);
            s2n_stuffer_free(&input_stuffer);
        }

        EXPECT_SUCCESS(s2n_pkey_free(&rsa_public_key));
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_pss_cert_chain));
    #endif
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_cert_chain));
    END_TEST();
}
