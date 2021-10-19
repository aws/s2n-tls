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

#include <openssl/crypto.h>

#include "crypto/s2n_fips.h"

static int s2n_fips_mode = 0;

int s2n_fips_init(void)
{
    s2n_fips_mode = 0;

    /* FIPS mode can be checked if OpenSSL was configured and built for FIPS which then defines OPENSSL_FIPS.
     *
     * AWS-LC always define FIPS_mode() that you can call and check what the library was built with. It does not define
     * a public OPENSSL_FIPS/AWSLC_FIPS macro that we can (or should) check here */
#if defined(OPENSSL_FIPS) || defined(OPENSSL_IS_AWSLC)
    FIPS_mode_set(1);
    if (FIPS_mode()) {
        s2n_fips_mode = 1;
    }
#endif
    return 0;
}

/* Return 1 if FIPS mode is enabled, 0 otherwise. FIPS mode must be enabled prior to calling s2n_init(). */
int s2n_is_in_fips_mode(void)
{
    return s2n_fips_mode;
}
