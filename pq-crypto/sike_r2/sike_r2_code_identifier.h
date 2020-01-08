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

#ifndef S2N_SIKE_R2_CODE_IDENTIFIER_H
#define S2N_SIKE_R2_CODE_IDENTIFIER_H

#ifndef S2N_NO_PQ_ASM
#ifndef __APPLE__
#ifdef __x86_64__
#define S2N_PQ_ASM
#endif
#endif
#endif

#ifndef S2N_PQ_ASM
#define S2N_PQ_GENERIC
#endif

#define ASM_CODE_IDENTIFIER 1
#define GENERIC_C_CODE_IDENTIFIER 2

// Simply returns either ASM_CODE_IDENTIFIER or GENERIC_C_CODE_IDENTIFIER depending on
// which file the function is defined in. See also tests/unit/s2n_sike_r2_verify_included_code_test.c
int sike_r2_fp_code_identifier();

#endif //S2N_SIKE_R2_CODE_IDENTIFIER_H
