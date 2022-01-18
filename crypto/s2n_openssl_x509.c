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
#include "crypto/s2n_openssl_x509.h"

int s2n_openssl_x509_stack_pop_free(STACK_OF(X509) **cert_chain)
{
    if (*cert_chain != NULL) {
        sk_X509_pop_free(*cert_chain, X509_free);
    }
    return S2N_SUCCESS;
}
