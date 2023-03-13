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

#include "s2n_test.h"
#include "tls/s2n_ktls.h"

#if defined(__linux__)
    #include "linux/version.h"
#endif

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* kTLS feature probe */
    {
#if defined(__linux__)
    /* kTLS support was first added to AL2 starting in 5.10.130. */
    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 130))
        EXPECT_TRUE(s2n_ktls_is_supported_on_platform());
    #endif
#endif
    };

    END_TEST();
}
