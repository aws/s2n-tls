/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <string.h>

#include "testlib/s2n_testlib.h"

#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"

#include "crypto/s2n_ecdsa.h"
#include "crypto/s2n_ecc_evp.h"
#include "crypto/s2n_fips.h"

#include "utils/s2n_safety.h"


static uint8_t unmatched_private_key[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MIIB+gIBAQQwuenHFMJsDm5tCQgthH8kGXQ1dHkKACmHH3ZqIGteoghhGow6vGmr\n"
    "xzA8gAdD2bJ0oIIBWzCCAVcCAQEwPAYHKoZIzj0BAQIxAP//////////////////\n"
    "///////////////////////+/////wAAAAAAAAAA/////zB7BDD/////////////\n"
    "/////////////////////////////v////8AAAAAAAAAAP////wEMLMxL6fiPufk\n"
    "mI4Fa+P4LRkYHZxu/oFBEgMUCI9QE4daxlY5jYou0Z0qhcjt0+wq7wMVAKM1kmqj\n"
    "GaJ6HQCJamdzpIJ6zaxzBGEEqofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJU\n"
    "KjhVAvJdv1UpbDpUXjhydgq3NhfeSpYmLG9dnpi/kpLcKfj0Hb0omhR86doxE7Xw\n"
    "uMAKYLHOHX6BnXpDHXyQ6g5fAjEA////////////////////////////////x2NN\n"
    "gfQ3Ld9YGg2ySLCneuzsGWrMxSlzAgEBoWQDYgAE8oYPSRINnKlr5ZBHWacYEq4Y\n"
    "j18l5f9yoMhBhpl7qvzf7uNFQ1SHzgHu0/v662d8Z0Pc0ujIms3/9uYxXVUY73vm\n"
    "iwVevOxBJ1GL0usqhWNqOKoNp048H4rCmfyMN97E\n"
    "-----END EC PRIVATE KEY-----\n";

int main(int argc, char **argv)
{
    struct s2n_stuffer certificate_in, certificate_out;
    struct s2n_stuffer ecdsa_key_in, ecdsa_key_out;
    struct s2n_stuffer unmatched_ecdsa_key_in, unmatched_ecdsa_key_out;
    struct s2n_blob b;
    char *cert_chain_pem;
    char *private_key_pem;

    const int supported_hash_algorithms[] = {
        S2N_HASH_NONE,
        S2N_HASH_MD5,
        S2N_HASH_SHA1,
        S2N_HASH_SHA224,
        S2N_HASH_SHA256,
        S2N_HASH_SHA384,
        S2N_HASH_SHA512,
        S2N_HASH_MD5_SHA1
    };

    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&ecdsa_key_in, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&ecdsa_key_out, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&unmatched_ecdsa_key_in, sizeof(unmatched_private_key)));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&unmatched_ecdsa_key_out, sizeof(unmatched_private_key)));
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));

    b.data = (uint8_t *) cert_chain_pem;
    b.size = strlen(cert_chain_pem) + 1;
    EXPECT_SUCCESS(s2n_stuffer_write(&certificate_in, &b));

    b.data = (uint8_t *) private_key_pem;
    b.size = strlen(private_key_pem) + 1;
    EXPECT_SUCCESS(s2n_stuffer_write(&ecdsa_key_in, &b));

    b.data = unmatched_private_key;
    b.size = sizeof(unmatched_private_key);
    EXPECT_SUCCESS(s2n_stuffer_write(&unmatched_ecdsa_key_in, &b));

    EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));
    EXPECT_SUCCESS(s2n_stuffer_private_key_from_pem(&ecdsa_key_in, &ecdsa_key_out));
    EXPECT_SUCCESS(s2n_stuffer_private_key_from_pem(&unmatched_ecdsa_key_in, &unmatched_ecdsa_key_out));

    struct s2n_pkey pub_key;
    struct s2n_pkey priv_key;
    struct s2n_pkey unmatched_priv_key;
    s2n_cert_type cert_type;

    b.size = s2n_stuffer_data_available(&certificate_out);
    b.data = s2n_stuffer_raw_read(&certificate_out, b.size);
    EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&pub_key, &cert_type, &b));

    b.size = s2n_stuffer_data_available(&ecdsa_key_out);
    b.data = s2n_stuffer_raw_read(&ecdsa_key_out, b.size);
    EXPECT_SUCCESS(s2n_asn1der_to_private_key(&priv_key, &b));
    
    b.size = s2n_stuffer_data_available(&unmatched_ecdsa_key_out);
    b.data = s2n_stuffer_raw_read(&unmatched_ecdsa_key_out, b.size);
    EXPECT_SUCCESS(s2n_asn1der_to_private_key(&unmatched_priv_key, &b));

    /* Verify that the public/private key pair match */
    EXPECT_SUCCESS(s2n_pkey_match(&pub_key, &priv_key));

    /* Try signing and verification with ECDSA */
    uint8_t inputpad[] = "Hello world!";
    struct s2n_blob signature, bad_signature;
    struct s2n_hash_state hash_one, hash_two;
    uint32_t maximum_signature_length = s2n_pkey_size(&priv_key);
    
    EXPECT_SUCCESS(s2n_alloc(&signature, maximum_signature_length));

    EXPECT_SUCCESS(s2n_hash_new(&hash_one));
    EXPECT_SUCCESS(s2n_hash_new(&hash_two));

    for (int i = 0; i < s2n_array_len(supported_hash_algorithms); i++) {
        int hash_alg = supported_hash_algorithms[i];
        
        if (!s2n_hash_is_available(hash_alg)) {
            /* Skip hash algorithms that are not available. */
            continue;
        }

        EXPECT_SUCCESS(s2n_hash_init(&hash_one, hash_alg));
        EXPECT_SUCCESS(s2n_hash_init(&hash_two, hash_alg));

        EXPECT_SUCCESS(s2n_hash_update(&hash_one, inputpad, sizeof(inputpad)));
        EXPECT_SUCCESS(s2n_hash_update(&hash_two, inputpad, sizeof(inputpad)));

        /* Reset signature size when we compute a new signature */
        signature.size = maximum_signature_length;
        
        EXPECT_SUCCESS(s2n_pkey_sign(&priv_key, &hash_one, &signature));
        EXPECT_SUCCESS(s2n_pkey_verify(&pub_key, &hash_two, &signature));
        
        EXPECT_SUCCESS(s2n_hash_reset(&hash_one));
        EXPECT_SUCCESS(s2n_hash_reset(&hash_two));
    }

    /* Mismatched public/private key should fail verification */
    EXPECT_SUCCESS(s2n_alloc(&bad_signature, s2n_pkey_size(&unmatched_priv_key)));

    EXPECT_FAILURE(s2n_pkey_match(&pub_key, &unmatched_priv_key));

    EXPECT_SUCCESS(s2n_pkey_sign(&unmatched_priv_key, &hash_one, &bad_signature));
    EXPECT_FAILURE(s2n_pkey_verify(&pub_key, &hash_two, &bad_signature));
    
    EXPECT_SUCCESS(s2n_free(&signature));
    EXPECT_SUCCESS(s2n_free(&bad_signature));
    
    EXPECT_SUCCESS(s2n_hash_free(&hash_one));
    EXPECT_SUCCESS(s2n_hash_free(&hash_two));
    
    EXPECT_SUCCESS(s2n_pkey_free(&pub_key));
    EXPECT_SUCCESS(s2n_pkey_free(&priv_key));
    EXPECT_SUCCESS(s2n_pkey_free(&unmatched_priv_key));
    
    EXPECT_SUCCESS(s2n_stuffer_free(&certificate_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&certificate_out));
    EXPECT_SUCCESS(s2n_stuffer_free(&ecdsa_key_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&ecdsa_key_out));
    EXPECT_SUCCESS(s2n_stuffer_free(&unmatched_ecdsa_key_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&unmatched_ecdsa_key_out));
    free(cert_chain_pem);
    free(private_key_pem);

    END_TEST();
}

