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

/*
 * This feature probe checks if the linked libcrypto provides the CBS
 * byte-cursor API (aws-lc / BoringSSL only). CBS is used for zero-copy
 * DER traversal by the zero-copy certificate verifier.
 * https://github.com/aws/aws-lc/blob/main/include/openssl/bytestring.h
 */

#include <openssl/bytestring.h>

int main()
{
    /* Usage in the zero-copy certificate parser (tls/s2n_cert_parse.c) */
    CBS cbs = { 0 };
    CBS_init(&cbs, NULL, 0);

    /* Contents-only traversal of a DER element */
    CBS contents = { 0 };
    CBS_get_asn1(&cbs, &contents, CBS_ASN1_SEQUENCE);

    /* Full-TLV (header included) traversal, required for the TBS span */
    CBS element = { 0 };
    CBS_get_any_asn1_element(&cbs, &element, NULL, NULL);

    return 0;
}
