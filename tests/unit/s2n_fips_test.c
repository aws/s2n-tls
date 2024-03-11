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

#include "crypto/s2n_fips.h"

#include "api/s2n.h"
#include "s2n_test.h"

int main()
{
    BEGIN_TEST_NO_INIT();

    /* s2n_is_fips() fails before init */
    {
        bool fips = true;
        EXPECT_FAILURE_WITH_ERRNO(s2n_is_fips(&fips), S2N_ERR_NOT_INITIALIZED);
        EXPECT_FALSE(fips);
    }

    EXPECT_SUCCESS(s2n_init());

    /* Test s2n_is_fips() after init */
    {
        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_is_fips(NULL), S2N_ERR_NULL);

        /* FIPS value matches s2n_is_in_fips_mode() */
        {
            bool fips = false;
            EXPECT_SUCCESS(s2n_is_fips(&fips));
            EXPECT_EQUAL(fips, s2n_is_in_fips_mode());
        }
    }

    END_TEST();
}
