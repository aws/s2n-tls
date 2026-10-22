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

#include <openssl/x509.h>

/* OpenSSL 4.0 changed the X509 getters to return const pointers, so callers
 * must hold the results in const variables. Older OpenSSL headers declare the
 * corresponding read-only APIs with non-const parameters, which rejects those
 * const variables. This probe compiles the const-qualified usage with -Werror
 * so that it only succeeds when the libcrypto headers accept const arguments
 * throughout.
 */
int main()
{
    X509 *x509_cert = NULL;

    const X509_NAME *subject = X509_get_subject_name(x509_cert);
    int idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    (void) idx;

    const X509_NAME_ENTRY *name_entry = X509_NAME_get_entry(subject, 0);
    const ASN1_STRING *asn1_str = X509_NAME_ENTRY_get_data(name_entry);
    (void) asn1_str;

    const X509_EXTENSION *x509_ext = X509_get_ext(x509_cert, 0);
    const ASN1_OBJECT *asn1_obj = X509_EXTENSION_get_object(x509_ext);
    (void) asn1_obj;
    const ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(x509_ext);
    (void) ext_data;

    return 0;
}
