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
 *
 */

#include "s2n_test.h"
#include "tests/testlib/s2n_testlib.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_cipher_suites.h"
#include "crypto/s2n_fips.h"

#define RSP_FILE_NAME "kats/hybrid_ecdhe_sike_r2.kat"
#define SERVER_KEY_MESSAGE_LENGTH 663
#define CLIENT_KEY_MESSAGE_LENGTH 414

int main(int argc, char **argv) {
    BEGIN_TEST();

#if !defined(S2N_NO_PQ)

    if (s2n_is_in_fips_mode()) {
        /* There is no support for PQ KEMs while in FIPS mode */
        END_TEST();
    }
    EXPECT_SUCCESS(s2n_test_hybrid_ecdhe_kem_with_kat(&s2n_sike_p434_r2, &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384,
            "KMS-PQ-TLS-1-0-2020-02", RSP_FILE_NAME, SERVER_KEY_MESSAGE_LENGTH, CLIENT_KEY_MESSAGE_LENGTH));

#endif

    END_TEST();
}
