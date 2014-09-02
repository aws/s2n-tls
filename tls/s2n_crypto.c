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

#include <string.h>

#include "tls/s2n_crypto.h"

void s2n_increment_sequence_number(uint8_t sequence_number[S2N_TLS_SEQUENCE_NUM_LEN])
{
    for (int i = S2N_TLS_SEQUENCE_NUM_LEN - 1; i >= 0; i--) {
        sequence_number[i] += 1;
        if (sequence_number[i]) {
            break;
        }
        /* seq[i] wrapped, so let it carry */
    }
}

int s2n_zero_sequence_number(uint8_t sequence_number[S2N_TLS_SEQUENCE_NUM_LEN], const char **err)
{
    if (memset(sequence_number, 0, S2N_TLS_SEQUENCE_NUM_LEN) != sequence_number) {
        *err = "memset failed";
        return -1;
    }
    return 0;
}
