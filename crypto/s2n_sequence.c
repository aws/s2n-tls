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

#include "crypto/s2n_sequence.h"

#include "error/s2n_errno.h"

#include "utils/s2n_blob.h"

int s2n_increment_sequence_number(struct s2n_blob *sequence_number)
{
    for (int i = sequence_number->size - 1; i >= 0; i--) {
        sequence_number->data[i] += 1;
        if (sequence_number->data[i]) {
            break;
        }

        /* RFC 5246 6.1: If a TLS implementation would need to wrap a sequence number, it must
         * renegotiate instead. We don't support renegotiation. Caller needs to create a new session.
         * This condition is very unlikely. It requires 2^64 - 1 records to be sent.
         */
        S2N_ERROR_IF(i == 0, S2N_ERR_RECORD_LIMIT);

        /* seq[i] wrapped, so let it carry */
    }

    return 0;
}
