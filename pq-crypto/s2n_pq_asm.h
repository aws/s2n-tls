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

#pragma once

#ifndef S2N_BLOCK_NONPORTABLE_OPTIMIZATIONS
#define S2N_BLOCK_NONPORTABLE_OPTIMIZATIONS 0
#endif

#define S2N_ANY_NONPORTABLE_OPTIMIZATIONS_ENABLED   (__AVX__ || __AVX2__ || __BMI2__)

#if S2N_BLOCK_NONPORTABLE_OPTIMIZATIONS && S2N_ANY_NONPORTABLE_OPTIMIZATIONS_ENABLED
#define S2N_ENSURE_PORTABLE_OPTIMIZATIONS \
    #error "Compiling portable code with non-portable assembly optimizations. This can result in runtime crashes if artifacts are deployed to older CPU's without these CPU instructions"
#else
#define S2N_ENSURE_PORTABLE_OPTIMIZATIONS
#endif
