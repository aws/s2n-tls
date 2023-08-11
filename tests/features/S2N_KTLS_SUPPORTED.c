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
    /* Struct defined when kTLS support was added to linux
     * https://github.com/torvalds/linux/blob/3c4d7559159bfe1e3b94df3a657b2cda3a34e218/include/uapi/linux/tls.h
     */
    struct tls12_crypto_info_aes_gcm_128 aes_crypto_info;
    struct tls_crypto_info crypto_info;

    int get_record_type = TLS_GET_RECORD_TYPE;
    int set_record_type = TLS_SET_RECORD_TYPE;

    return 0;
}
