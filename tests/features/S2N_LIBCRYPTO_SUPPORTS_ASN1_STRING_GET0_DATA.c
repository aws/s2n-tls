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

#include <openssl/asn1.h>

int main()
{
    /* ASN1_STRING_get0_data() replaces both direct ASN1_STRING member access
     * and ASN1_STRING_data(), which were removed in OpenSSL 4.0.
     */
    const ASN1_STRING *asn1_str = NULL;
    const unsigned char *data = ASN1_STRING_get0_data(asn1_str);
    (void) data;

    return 0;
}
