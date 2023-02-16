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

#include "crypto/s2n_evp_signing.h"

#include "crypto/s2n_ecdsa.h"
#include "crypto/s2n_fips.h"
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

static bool s2n_hash_alg_is_supported(s2n_signature_algorithm sig_alg, s2n_hash_algorithm hash_alg)
{
    return (hash_alg != S2N_HASH_NONE) && (hash_alg != S2N_HASH_MD5)
            && (hash_alg != S2N_HASH_MD5_SHA1 || sig_alg == S2N_SIGNATURE_RSA);
}

static S2N_RESULT s2n_test_hash_init(struct s2n_hash_state *hash_state, s2n_hash_algorithm hash_alg)
{
    RESULT_GUARD_POSIX(s2n_hash_init(hash_state, hash_alg));
    RESULT_GUARD_POSIX(s2n_hash_allow_md5_for_fips(hash_state));
    RESULT_GUARD_POSIX(s2n_hash_update(hash_state, input_data, s2n_array_len(input_data)));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_setup_public_key(struct s2n_pkey *public_key, struct s2n_cert_chain_and_key *chain)
{
    s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
    EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(public_key, &pkey_type,
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
        struct s2n_pkey *public_key,
        struct s2n_blob *evp_signature, struct s2n_blob *expected_signature)
{
    DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
    RESULT_GUARD_POSIX(s2n_hash_new(&hash_state));

    /* Verify that the EVP methods can verify their own signature */
    RESULT_GUARD(s2n_test_hash_init(&hash_state, hash_alg));
    RESULT_GUARD_POSIX(s2n_evp_verify(public_key, sig_alg, &hash_state, evp_signature));

    /* Verify that using the pkey directly can verify own signature */
    RESULT_GUARD(s2n_test_hash_init(&hash_state, hash_alg));
    RESULT_GUARD_POSIX(s2n_pkey_verify(public_key, sig_alg, &hash_state, evp_signature));

    /* Verify that the EVP methods can verify the known good signature */
    RESULT_GUARD(s2n_test_hash_init(&hash_state, hash_alg));
    RESULT_GUARD_POSIX(s2n_evp_verify(public_key, sig_alg, &hash_state, expected_signature));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Sanity check that we're enabling evp signing properly.
     * awslc-fips is known to require evp signing.
     */
    if (s2n_is_in_fips_mode() && s2n_libcrypto_is_awslc()) {
        EXPECT_TRUE(s2n_evp_signing_supported());
    }

    if (!s2n_evp_signing_supported()) {
        END_TEST();
    }

    DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
    EXPECT_SUCCESS(s2n_hash_new(&hash_state));

    struct s2n_cert_chain_and_key *rsa_cert_chain = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_cert_chain,
            S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY));

    /* Test that unsupported hash algs are treated as invalid.
     * Later tests will ignore unsupported algs, so ensure they are actually invalid. */
    {
        /* This pkey should never actually be needed -- any pkey will do */
        struct s2n_pkey *pkey = rsa_cert_chain->private_key;

        for (s2n_signature_algorithm sig_alg = 0; sig_alg <= UINT8_MAX; sig_alg++) {
            for (s2n_hash_algorithm hash_alg = 0; hash_alg < S2N_HASH_SENTINEL; hash_alg++) {
                if (s2n_hash_alg_is_supported(sig_alg, hash_alg)) {
                    continue;
                }

                s2n_stack_blob(evp_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
                EXPECT_ERROR_WITH_ERRNO(s2n_test_evp_sign(sig_alg, hash_alg, pkey, &evp_signature),
                        S2N_ERR_HASH_INVALID_ALGORITHM);
                EXPECT_ERROR_WITH_ERRNO(s2n_test_evp_verify(sig_alg, hash_alg, pkey, &evp_signature, &evp_signature),
                        S2N_ERR_HASH_INVALID_ALGORITHM);
            }
        }
    };

    /* EVP signing must match RSA signing */
    {
        s2n_signature_algorithm sig_alg = S2N_SIGNATURE_RSA;

        DEFER_CLEANUP(struct s2n_pkey public_key_parsed = { 0 }, s2n_pkey_free);
        EXPECT_OK(s2n_setup_public_key(&public_key_parsed, rsa_cert_chain));

        struct s2n_pkey *private_key = rsa_cert_chain->private_key;
        struct s2n_pkey *public_key = &public_key_parsed;
        EXPECT_PKEY_USES_EVP_SIGNING(private_key);
        EXPECT_PKEY_USES_EVP_SIGNING(public_key);

        for (s2n_hash_algorithm hash_alg = 0; hash_alg < S2N_HASH_SENTINEL; hash_alg++) {
            if (!s2n_hash_alg_is_supported(sig_alg, hash_alg)) {
                continue;
            }

            /* Calculate the signature using EVP methods */
            s2n_stack_blob(evp_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
            EXPECT_OK(s2n_test_evp_sign(sig_alg, hash_alg, private_key, &evp_signature));

            /* Calculate the signature using RSA methods */
            s2n_stack_blob(rsa_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
            EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
            EXPECT_SUCCESS(s2n_rsa_pkcs1v15_sign(private_key, &hash_state, &rsa_signature));

            /* Verify that the EVP methods can verify both signatures */
            EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &evp_signature, &rsa_signature));

            /* Verify that the RSA methods can verify the EVP signature */
            EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
            EXPECT_SUCCESS(s2n_rsa_pkcs1v15_verify(public_key, &hash_state, &evp_signature));
        }
    };

    /* EVP signing must match ECDSA signing */
    {
        s2n_signature_algorithm sig_alg = S2N_SIGNATURE_ECDSA;

        struct s2n_cert_chain_and_key *ecdsa_cert_chain = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_cert_chain,
                S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));
        DEFER_CLEANUP(struct s2n_pkey public_key_parsed = { 0 }, s2n_pkey_free);
        EXPECT_OK(s2n_setup_public_key(&public_key_parsed, ecdsa_cert_chain));

        struct s2n_pkey *private_key = ecdsa_cert_chain->private_key;
        struct s2n_pkey *public_key = &public_key_parsed;
        EXPECT_PKEY_USES_EVP_SIGNING(private_key);
        EXPECT_PKEY_USES_EVP_SIGNING(public_key);

        for (s2n_hash_algorithm hash_alg = 0; hash_alg < S2N_HASH_SENTINEL; hash_alg++) {
            if (!s2n_hash_alg_is_supported(sig_alg, hash_alg)) {
                continue;
            }

            /* Calculate the signature using EVP methods */
            s2n_stack_blob(evp_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
            EXPECT_OK(s2n_test_evp_sign(sig_alg, hash_alg, private_key, &evp_signature));

            /* Calculate the signature using ECDSA methods */
            s2n_stack_blob(ecdsa_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
            EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
            EXPECT_SUCCESS(s2n_ecdsa_sign(private_key, sig_alg, &hash_state, &ecdsa_signature));

            /* Verify that the EVP methods can verify both signatures */
            EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &evp_signature, &ecdsa_signature));

            /* Verify that the ECDSA methods can verify the EVP signature */
            EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
            EXPECT_SUCCESS(s2n_ecdsa_verify(public_key, sig_alg, &hash_state, &evp_signature));
        }

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert_chain));
    };

    /* EVP signing must match RSA-PSS-RSAE signing */
    if (s2n_is_rsa_pss_signing_supported()) {
        s2n_signature_algorithm sig_alg = S2N_SIGNATURE_RSA_PSS_RSAE;

        DEFER_CLEANUP(struct s2n_pkey public_key_parsed = { 0 }, s2n_pkey_free);
        EXPECT_OK(s2n_setup_public_key(&public_key_parsed, rsa_cert_chain));

        struct s2n_pkey *private_key = rsa_cert_chain->private_key;
        struct s2n_pkey *public_key = &public_key_parsed;
        EXPECT_PKEY_USES_EVP_SIGNING(private_key);
        EXPECT_PKEY_USES_EVP_SIGNING(public_key);

        for (s2n_hash_algorithm hash_alg = 0; hash_alg < S2N_HASH_SENTINEL; hash_alg++) {
            if (!s2n_hash_alg_is_supported(sig_alg, hash_alg)) {
                continue;
            }

            /* Calculate the signature using EVP methods */
            s2n_stack_blob(evp_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
            EXPECT_OK(s2n_test_evp_sign(sig_alg, hash_alg, private_key, &evp_signature));

            /* Calculate the signature using RSA-PSS methods */
            s2n_stack_blob(rsa_pss_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
            EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
            EXPECT_SUCCESS(s2n_rsa_pss_sign(private_key, &hash_state, &rsa_pss_signature));

            /* Verify that the EVP methods can verify both signatures */
            EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &evp_signature, &rsa_pss_signature));

            /* Verify that the RSA-PSS methods can verify the EVP signature */
            EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
            EXPECT_SUCCESS(s2n_rsa_pss_verify(public_key, &hash_state, &evp_signature));
        }
    }

    /* EVP signing must match RSA-PSS-PSS signing */
    if (s2n_is_rsa_pss_certs_supported()) {
        s2n_signature_algorithm sig_alg = S2N_SIGNATURE_RSA_PSS_PSS;

        struct s2n_cert_chain_and_key *rsa_pss_cert_chain = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_pss_cert_chain,
                S2N_RSA_PSS_2048_SHA256_LEAF_CERT, S2N_RSA_PSS_2048_SHA256_LEAF_KEY));
        DEFER_CLEANUP(struct s2n_pkey public_key_parsed = { 0 }, s2n_pkey_free);
        EXPECT_OK(s2n_setup_public_key(&public_key_parsed, rsa_pss_cert_chain));

        struct s2n_pkey *private_key = rsa_pss_cert_chain->private_key;
        struct s2n_pkey *public_key = &public_key_parsed;
        EXPECT_PKEY_USES_EVP_SIGNING(private_key);
        EXPECT_PKEY_USES_EVP_SIGNING(public_key);

        for (s2n_hash_algorithm hash_alg = 0; hash_alg < S2N_HASH_SENTINEL; hash_alg++) {
            if (!s2n_hash_alg_is_supported(sig_alg, hash_alg)) {
                continue;
            }

            /* Calculate the signature using EVP methods */
            s2n_stack_blob(evp_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
            EXPECT_OK(s2n_test_evp_sign(sig_alg, hash_alg, private_key, &evp_signature));

            /* Calculate the signature using RSA-PSS methods */
            s2n_stack_blob(rsa_pss_signature, OUTPUT_DATA_SIZE, OUTPUT_DATA_SIZE);
            EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
            EXPECT_SUCCESS(s2n_rsa_pss_sign(private_key, &hash_state, &rsa_pss_signature));

            /* Verify that the EVP methods can verify both signatures */
            EXPECT_OK(s2n_test_evp_verify(sig_alg, hash_alg, public_key, &evp_signature, &rsa_pss_signature));

            /* Verify that the RSA-PSS methods can verify the EVP signature */
            EXPECT_OK(s2n_test_hash_init(&hash_state, hash_alg));
            EXPECT_SUCCESS(s2n_rsa_pss_verify(public_key, &hash_state, &evp_signature));
        }

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_pss_cert_chain));
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_cert_chain));
    END_TEST();
}
