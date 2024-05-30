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

#include <openssl/rsa.h>

#include "../../crypto/s2n_openssl.h"

#if !((S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 1) || defined(OPENSSL_IS_AWSLC)) && !defined(LIBRESSL_VERSION_NUMBER) && !defined(OPENSSL_IS_BORINGSSL))
    #error "RSA-PSS signing not supported"
#endif

int main()
{
    RSA_get0_pss_params(NULL);
    return 0;
}
