/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <sys/param.h>

#include "pq-random.h"
#include "utils/s2n_mem.h"


static int (*random_data_generator)(struct s2n_blob *) = &s2n_get_private_random_data;

int initialize_pq_crypto_generator(int (*generator_ptr)(struct s2n_blob *))
{
    if (generator_ptr == NULL) {
        return -1;
    }
    random_data_generator = generator_ptr;
    return 0;
}

int get_random_bytes(OUT unsigned char *buffer, unsigned int num_bytes)
{
    struct s2n_blob out = {.data = buffer,.size = num_bytes };
    return random_data_generator(&out);
}
