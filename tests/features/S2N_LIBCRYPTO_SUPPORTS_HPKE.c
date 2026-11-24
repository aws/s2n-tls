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

/* OpenSSL 3.2+ also ships <openssl/hpke.h>, but with the OSSL_HPKE_* API.
 * Reference the EVP_HPKE_* symbols so that only the AWS-LC and BoringSSL API passes.
 * crypto/s2n_hpke.c also requires AWS-LC: see crypto/s2n_hpke.h. */
#include <openssl/hpke.h>

int main()
{
    EVP_hpke_x25519_hkdf_sha256();
    EVP_hpke_hkdf_sha256();
    EVP_hpke_aes_128_gcm();
    EVP_HPKE_CTX_setup_recipient(NULL, NULL, NULL, NULL, NULL, 0, NULL, 0);
    return 0;
}
