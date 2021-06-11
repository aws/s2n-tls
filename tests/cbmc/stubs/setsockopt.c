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

#include <sys/socket.h>
#include <cbmc_proof/nondet.h>

/* https://pubs.opengroup.org/onlinepubs/009695399/functions/setsockopt.html */
int setsockopt(int fst, int snd, int thd, const void *vd, socklen_t st)
{
    return nondet_bool() ? 0 : -1;
}
