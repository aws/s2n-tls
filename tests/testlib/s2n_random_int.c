/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdint.h>

#include "testlib/s2n_testlib.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

int s2n_random_int(uint32_t max, uint32_t *r, const char **err)
{
    uint8_t pad[4];
    uint32_t n;
    
    do {
        GUARD( s2n_get_random_data(pad, 4, err) );

        n  = pad[0] << 24;
        n |= pad[1] << 16;
        n |= pad[2] << 8;
        n |= pad[3];

    } while (n >= (0xffffffff - (0xffffffff % max)));

    *r = (n % max);

    return 0;
}
