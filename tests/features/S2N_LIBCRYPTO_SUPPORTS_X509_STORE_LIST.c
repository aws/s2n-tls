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

int main() {
    /* X509_STORE_get0_objects appears to be the earliest method available that
     * can retrieve all certificates from an X509_STORE.
     *
     * X509_STORE_get_by_subject and X509_STORE_get1_certs are available even
     * earlier (Openssl-1.0.2), but both require known X509_NAMEs.
     */
    STACK_OF(X509_OBJECT) *objects = X509_STORE_get0_objects(NULL);
    X509 *cert = X509_OBJECT_get0_X509(NULL);
    /* We could use i2d_X509_NAME instead if necessary, but X509_NAME_get0_der
     * should be available where X509_STORE_get0_objects is */
    X509_NAME_get0_der(NULL, NULL, NULL);
    return 0;
}
