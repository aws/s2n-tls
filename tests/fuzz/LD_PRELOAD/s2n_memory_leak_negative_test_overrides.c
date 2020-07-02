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

#include "api/s2n.h"
#include "utils/s2n_blob.h"

int s2n_free(struct s2n_blob *b)
{
    /* This will cause large amounts of memory leaks. This should be caught by LibFuzzer as a negative fuzz test to
     * ensure that LibFuzzer will catch these memory leaks.
     */
    return S2N_SUCCESS;
}
