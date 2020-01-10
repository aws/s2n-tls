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
#include "tests/testlib/s2n_nist_kats.h"
#include "tests/testlib/s2n_testlib.h"
#include "tls/s2n_kem.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_blob.h"

#define RSP_FILE_NAME "../unit/kats/bike_r1.kat"

/* This fuzz test uses the first private key from tests/unit/kats/bike_r1.kat, the valid ciphertext generated with the
 * public key was copied to corpus/s2n_bike_r1_fuzz_test/valid_ciphertext */

static struct s2n_kem_keypair server_kem_keys = {.negotiated_kem = &s2n_bike1_l1_r1};

static void s2n_fuzz_atexit()
{
    s2n_free(&server_kem_keys.private_key);
    s2n_cleanup();
}

int LLVMFuzzerInitialize(const uint8_t *buf, size_t len)
{
    GUARD(s2n_init());
    GUARD(atexit(s2n_fuzz_atexit));

    GUARD(s2n_alloc(&server_kem_keys.private_key, s2n_bike1_l1_r1.private_key_length));

    FILE *kat_file = fopen(RSP_FILE_NAME, "r");
    notnull_check(kat_file);
    GUARD(ReadHex(kat_file, server_kem_keys.private_key.data, s2n_bike1_l1_r1.private_key_length, "sk = "));

    fclose(kat_file);

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    struct s2n_blob server_shared_secret = {0};
    struct s2n_blob ciphertext = {0};
    GUARD(s2n_alloc(&ciphertext, len));

    /* Need to memcpy since blobs expect a non-const value and LLVMFuzzer does expect a const */
    memcpy_check(ciphertext.data, buf, len);

    /* Run the test, don't use GUARD since the memory needs to be cleaned up and decapsulate will most likely fail */
    s2n_kem_decapsulate(&server_kem_keys, &server_shared_secret, &ciphertext);

    GUARD(s2n_free(&ciphertext));

    /* The above s2n_kem_decapsulate could fail before ever allocating the server_shared_secret */
    if (server_shared_secret.allocated) {
        GUARD(s2n_free(&server_shared_secret));
    }
    return 0;
}
