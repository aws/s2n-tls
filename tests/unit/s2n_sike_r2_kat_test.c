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
 * Modified from PQCgenKAT_kem.c
 * Created by Bassham, Lawrence E (Fed) on 8/29/17.
 * Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
 */

#include "s2n_test.h"
#include "tests/testlib/s2n_testlib.h"
#include "tls/s2n_kem.h"
#include "crypto/s2n_fips.h"

#define RSP_FILE "kats/sike_r2.kat"

int main(int argc, char **argv, char **envp) {
    BEGIN_TEST();

#if !defined(S2N_NO_PQ)

    if (s2n_is_in_fips_mode()) {
        /* There is no support for PQ KEMs while in FIPS mode */
        END_TEST();
    }

    EXPECT_SUCCESS(s2n_test_kem_with_kat(&s2n_sike_p434_r2, RSP_FILE));

#endif

    END_TEST();
}
