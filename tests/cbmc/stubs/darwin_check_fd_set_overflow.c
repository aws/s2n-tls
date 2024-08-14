/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cbmc_proof/nondet.h>

/* A reference to this function appears as a side-effect of  */
/* building on macOS with some versions of XCode installed   */
/* A dummy stub is supplied here to prevent CBMC complaining */
/* of a missing body.                                        */
int __darwin_check_fd_set_overflow(int x, const void *y, int z)
{
    return nondet_int();
}
