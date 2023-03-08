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

#include "utils/s2n_result.h"

#include <stdio.h>
#include <string.h>

#include "api/s2n.h"
#include "s2n_test.h"

int main(int argc, char **argv)
{
    s2n_result success = { S2N_SUCCESS };
    s2n_result failure = { S2N_FAILURE };

    EXPECT_TRUE(s2n_result_is_ok(success));
    EXPECT_FALSE(s2n_result_is_ok(failure));

    EXPECT_TRUE(s2n_result_is_error(failure));
    EXPECT_FALSE(s2n_result_is_error(success));
}
