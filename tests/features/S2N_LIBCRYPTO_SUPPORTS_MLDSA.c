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

#include <openssl/evp.h>

int main()
{
    int evp_pkey_id = EVP_PKEY_PQDSA;
    int nids[] = { NID_MLDSA44, NID_MLDSA65, NID_MLDSA87 };
    /* Required to calculate the mu hash for ML-DSA */
    EVP_PKEY_get_raw_public_key(NULL, NULL, NULL);
    return 0;
}
