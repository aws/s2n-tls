/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "tests/s2n_test.h"

#include "tls/s2n_kex.h"
#include "tls/s2n_kem.h"

#include "utils/s2n_safety.h"

#define TEST_PUBLIC_KEY_LENGTH  2
const char TEST_PUBLIC_KEY[] = {2, 2};
#define TEST_PRIVATE_KEY_LENGTH  3
const char TEST_PRIVATE_KEY[] = {3, 3, 3};
#define TEST_SHARED_SECRET_LENGTH  4
const char TEST_SHARED_SECRET[] = {4, 4, 4, 4};
#define TEST_CIPHERTEXT_LENGTH  5
const char TEST_CIPHERTEXT[] = {5, 5, 5, 5, 5};


int s2n_test_generate_keypair(unsigned char *public_key, unsigned char *private_key)
{
    memset(public_key, TEST_PUBLIC_KEY_LENGTH, TEST_PUBLIC_KEY_LENGTH);
    memset(private_key, TEST_PRIVATE_KEY_LENGTH, TEST_PRIVATE_KEY_LENGTH);
    return 0;
}
int s2n_test_encrypt(unsigned char *ciphertext, unsigned char *shared_secret, const unsigned char *public_key)
{
    GUARD(memcmp(public_key, TEST_PUBLIC_KEY, TEST_PUBLIC_KEY_LENGTH));
    memset(ciphertext, TEST_CIPHERTEXT_LENGTH, TEST_CIPHERTEXT_LENGTH);
    memset(shared_secret, TEST_SHARED_SECRET_LENGTH, TEST_SHARED_SECRET_LENGTH);
    return 0;
}
int s2n_test_decrypt(unsigned char *shared_secret, const unsigned char *ciphertext, const unsigned char *private_key)
{
    GUARD(memcmp(ciphertext, TEST_CIPHERTEXT, TEST_CIPHERTEXT_LENGTH));
    GUARD(memcmp(private_key, TEST_PRIVATE_KEY, TEST_PRIVATE_KEY_LENGTH));
    memset(shared_secret, TEST_SHARED_SECRET_LENGTH, TEST_SHARED_SECRET_LENGTH);
    return 0;
}

const struct s2n_kem s2n_test_kem = {
        .publicKeySize = TEST_PUBLIC_KEY_LENGTH,
        .privateKeySize = TEST_PRIVATE_KEY_LENGTH,
        .sharedSecretKeySize = TEST_SHARED_SECRET_LENGTH,
        .ciphertextSize = TEST_CIPHERTEXT_LENGTH,
        .generate_keypair = &s2n_test_generate_keypair,
        .encrypt = &s2n_test_encrypt,
        .decrypt = &s2n_test_decrypt,
};

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_kem_params server_params = {0};

    EXPECT_SUCCESS(s2n_kem_generate_key_pair(&s2n_test_kem, &server_params));
    EXPECT_EQUAL(TEST_PUBLIC_KEY_LENGTH, server_params.public_key.size);
    EXPECT_EQUAL(TEST_PRIVATE_KEY_LENGTH, server_params.private_key.size);
    EXPECT_BYTEARRAY_EQUAL(TEST_PUBLIC_KEY, server_params.public_key.data, TEST_PUBLIC_KEY_LENGTH);
    EXPECT_BYTEARRAY_EQUAL(TEST_PRIVATE_KEY, server_params.private_key.data, TEST_PRIVATE_KEY_LENGTH);


    struct s2n_kem_params client_params = {0};
    // This would be handled by client/server key exchange methods which isn't being tested
    GUARD(s2n_alloc(&client_params.public_key, TEST_PUBLIC_KEY_LENGTH));
    memset(client_params.public_key.data, TEST_PUBLIC_KEY_LENGTH, TEST_PUBLIC_KEY_LENGTH);

    struct s2n_blob client_shared_secret = {0};
    struct s2n_blob ciphertext = {0};
    EXPECT_SUCCESS(s2n_kem_generate_shared_secret(&s2n_test_kem, &client_params, &client_shared_secret, &ciphertext));
    EXPECT_EQUAL(TEST_SHARED_SECRET_LENGTH, client_shared_secret.size);
    EXPECT_EQUAL(TEST_CIPHERTEXT_LENGTH, ciphertext.size);
    EXPECT_BYTEARRAY_EQUAL(TEST_SHARED_SECRET, client_shared_secret.data, TEST_SHARED_SECRET_LENGTH);
    EXPECT_BYTEARRAY_EQUAL(TEST_CIPHERTEXT, ciphertext.data, TEST_CIPHERTEXT_LENGTH);

    struct s2n_blob server_shared_secret = {0};
    EXPECT_SUCCESS(s2n_kem_decrypt_shared_secret(&s2n_test_kem, &server_params, &server_shared_secret, &ciphertext));
    EXPECT_EQUAL(TEST_SHARED_SECRET_LENGTH, server_shared_secret.size);
    EXPECT_BYTEARRAY_EQUAL(TEST_SHARED_SECRET, server_shared_secret.data, TEST_SHARED_SECRET_LENGTH);

    EXPECT_SUCCESS(s2n_free(&client_shared_secret));
    EXPECT_SUCCESS(s2n_free(&server_shared_secret));
    EXPECT_SUCCESS(s2n_free(&ciphertext));
    EXPECT_SUCCESS(s2n_free(&client_params.public_key));
    EXPECT_SUCCESS(s2n_free(&server_params.public_key));
    EXPECT_SUCCESS(s2n_free(&server_params.private_key));

    END_TEST();
}
