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

/* Gate kTLS support only to Linux. Add other platforms once they have been tested. */
#if defined(__linux__)
    #include <linux/tls.h>
#endif

int main()
{
    /* Initially ktls only supported AES-128 and TLS1.2:
     * https://github.com/torvalds/linux/blob/3c4d7559159bfe1e3b94df3a657b2cda3a34e218/include/uapi/linux/tls.h
     *
     * However, for simplicity our ktls probe will also require AES-256 and TLS1.3.
     * If this prevents some customers from using ktls, we can split our single ktls
     * feature probe into more fine-grained feature probes.
     */
    int versions[] = { TLS_1_2_VERSION, TLS_1_3_VERSION };
    int cipher_types[] = { TLS_CIPHER_AES_GCM_128, TLS_CIPHER_AES_GCM_256 };

    struct tls12_crypto_info_aes_gcm_128 aes_crypto_info_128 = { 0 };
    struct tls12_crypto_info_aes_gcm_256 aes_crypto_info_256 = { 0 };
    int operations[] = { TLS_GET_RECORD_TYPE, TLS_SET_RECORD_TYPE };
    return 0;
}
