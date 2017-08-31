/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

/* Per https://wiki.openssl.org/index.php/Manual:OPENSSL_VERSION_NUMBER(3)
 * OPENSSL_VERSION_NUMBER in hex is: MNNFFRBB major minor fix final beta/patch.
 * bitwise: MMMMNNNNNNNNFFFFFFFFRRRRBBBBBBBB
 * For our purposes we're only concerned about major/minor/fix. Patch versions don't usually introduce
 * features.
 */
#define S2N_OPENSSL_VERSION_AT_LEAST(major, minor, fix) \
    (OPENSSL_VERSION_NUMBER >= ((major << 28) + (minor << 20) + (fix << 12)))
