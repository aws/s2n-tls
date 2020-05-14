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

#include "utils/s2n_random.h"
#include "utils/s2n_result.h"
#include "pq_utils.h"

S2N_RESULT get_random_bytes(OUT unsigned char *buffer, unsigned int num_bytes)
{
    struct s2n_blob out = {.data = buffer,.size = num_bytes };
    return s2n_get_private_random_data(&out);
}
