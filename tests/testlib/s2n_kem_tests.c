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

#include "tls/s2n_kem.h"
#include "tests/testlib/s2n_nist_kats.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

#define SEED_LENGTH 48
uint8_t kat_entropy_buff[SEED_LENGTH] = {0};
struct s2n_blob kat_entropy_blob = {.size = SEED_LENGTH, .data = kat_entropy_buff};

int kat_entropy(struct s2n_blob *blob)
{
    eq_check(blob->size, kat_entropy_blob.size);
    blob->data = kat_entropy_blob.data;
    return 0;
}

int s2n_test_kem_with_kat(const struct s2n_kem *kem, const char *kat_file_name)
{
    notnull_check(kem);

    FILE *kat_file = fopen(kat_file_name, "r");
    notnull_check(kat_file);

    uint8_t *ct, *client_shared_secret, *pk, *sk, *server_shared_secret, *pk_answer, *sk_answer, *ct_answer, *ss_answer;
    /* Client side variables */
    notnull_check(ct = malloc(kem->ciphertext_length));
    notnull_check(client_shared_secret = malloc(kem->shared_secret_key_length));

    /* Server side variables */
    notnull_check(pk = malloc(kem->public_key_length));
    notnull_check(sk = malloc(kem->private_key_length));
    notnull_check(server_shared_secret = malloc(kem->shared_secret_key_length));

    /* Known answer variables */
    notnull_check(pk_answer = malloc(kem->public_key_length));
    notnull_check(sk_answer = malloc(kem->private_key_length));
    notnull_check(ct_answer = malloc(kem->ciphertext_length));
    notnull_check(ss_answer = malloc(kem->shared_secret_key_length));

    s2n_stack_blob(personalization_string, SEED_LENGTH, SEED_LENGTH);

    for (int32_t i = 0; i < NUM_OF_KATS; i++) {
        /* Verify test index */
        int32_t count = 0;
        GUARD(FindMarker(kat_file, "count = "));
        gt_check(fscanf(kat_file, "%d", &count), 0);
        eq_check(count, i);

        /* Set the NIST rng to the same state the response file was created with */
        GUARD(ReadHex(kat_file, kat_entropy_blob.data, SEED_LENGTH, "seed = "));
        struct s2n_drbg kat_drbg = {.entropy_generator = kat_entropy};
        GUARD(s2n_drbg_instantiate(&kat_drbg, &personalization_string, S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR));
        GUARD(s2n_set_private_drbg_for_test(kat_drbg));

        /* Generate the public/private key pair */
        GUARD(kem->generate_keypair(pk, sk));

        /* Create a shared secret and use the public key to encrypt it */
        GUARD(kem->encapsulate(ct, client_shared_secret, pk));

        /* Use the private key to decrypt the ct to get the shared secret */
        GUARD(kem->decapsulate(server_shared_secret, ct, sk));

        /* Read the KAT values */
        GUARD(ReadHex(kat_file, pk_answer, kem->public_key_length, "pk = "));
        GUARD(ReadHex(kat_file, sk_answer, kem->private_key_length, "sk = "));
        GUARD(ReadHex(kat_file, ct_answer, kem->ciphertext_length, "ct = "));
        GUARD(ReadHex(kat_file, ss_answer, kem->shared_secret_key_length, "ss = "));

        /* Test the client and server got the same value */
        eq_check(memcmp(client_shared_secret, server_shared_secret, kem->shared_secret_key_length), 0);

        /* Compare the KAT values */
        eq_check(memcmp(pk_answer, pk, kem->public_key_length), 0);
        eq_check(memcmp(sk_answer, sk, kem->private_key_length), 0);
        eq_check(memcmp(ct_answer, ct, kem->ciphertext_length), 0);
        eq_check(memcmp(ss_answer, server_shared_secret, kem->shared_secret_key_length ), 0);
    }
    fclose(kat_file);
    free(ct);
    free(client_shared_secret);
    free(pk);
    free(sk);
    free(server_shared_secret);
    free(pk_answer);
    free(sk_answer);
    free(ct_answer);
    free(ss_answer);

    return 0;
}
