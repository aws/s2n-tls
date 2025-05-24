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

#include "crypto/s2n_openssl_x509.h"

static int verify_custom_crit_oids_cb(X509_STORE_CTX *ctx, X509 *x509, STACK_OF(ASN1_OBJECT) *oids) {
    return 1;
}

int main()
{
    ASN1_OBJECT *critical_oid = NULL;
    X509_STORE_CTX *store_ctx = NULL;

    X509_STORE_CTX_add_custom_crit_oid(store_ctx, critical_oid);
    X509_STORE_CTX_set_verify_crit_oids(store_ctx, verify_custom_crit_oids_cb);

    return 0;
}
