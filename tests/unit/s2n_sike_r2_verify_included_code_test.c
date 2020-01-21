/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "pq-crypto/sike_r2/sike_r2_code_identifier.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /*
     * A little extra defense in depth to ensure that we are running the code
     * that we think we are. In particular, this helps prevent the scenario
     * where we accidentally include/run the generic C code when we actually
     * wanted to use the optimized assembly.
     */
#if defined(S2N_PQ_ASM)
    EXPECT_EQUAL(sike_r2_fp_code_identifier(), ASM_CODE_IDENTIFIER);
#elif defined(S2N_PQ_GENERIC)
    EXPECT_EQUAL(sike_r2_fp_code_identifier(), GENERIC_C_CODE_IDENTIFIER);
#else
    FAIL_MSG("Neither S2N_PQ_ASM nor S2N_PQ_GENERIC was defined. One of those must be defined.");
#endif

    END_TEST();
}
