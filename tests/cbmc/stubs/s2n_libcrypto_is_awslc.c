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

#include <stdbool.h>
#include "crypto/s2n_openssl.h"

static int flag = 0;
static bool s2n_awslc_flag = 0;

bool s2n_libcrypto_is_awslc()
{
   if (flag == 0) {
       s2n_awslc_flag = nondet_bool() ? 1 : 0;
       flag = 1;
   }
   return s2n_awslc_flag;
}
