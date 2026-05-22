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
 * This feature probe checks if the linked libcrypto has ENGINE support.
 * https://docs.openssl.org/1.0.2/man3/engine/
 */

/*
 * We would always expect the `openssl/engine.h` header to be available.
 * However, some platforms (CentOS 10,  Fedora 41, and RHEL 10) have reportedly
 * been removing the `openssl/engine.h` header.
 *
 * See the related issues:
 * - https://github.com/aws/s2n-tls/pull/4705
 * - https://github.com/aws/s2n-tls/pull/4873
 */
#include <openssl/engine.h>
/* LibreSSL requires <openssl/rand.h> include.
 * https://github.com/aws/s2n-tls/issues/153#issuecomment-129651643
 */
#include <openssl/rand.h>

int s2n_noop_rand(unsigned char *buf, int num)
{
    return 1;
}

int main()
{
    /* Init usage in utils/s2n_random.c */
    ENGINE *e = ENGINE_new();
    ENGINE_set_id(e, "id");
    ENGINE_set_name(e, "name");
    ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL);
    ENGINE_set_init_function(e, NULL);
    ENGINE_set_RAND(e, NULL);
    ENGINE_add(e);
    ENGINE_init(e);
    ENGINE_set_default(e, ENGINE_METHOD_RAND);

    /* Cleanup usage in utils/s2n_random.c */
    ENGINE_remove(e);
    ENGINE_finish(e);
    ENGINE_unregister_RAND(e);
    ENGINE_free(e);
    ENGINE_cleanup();
    RAND_set_rand_engine(NULL);
    RAND_set_rand_method(NULL);

    /* RAND_METHOD is gated behind S2N_LIBCRYPTO_SUPPORTS_ENGINE because AWS-LC has
     * a different signature for RAND_METHOD and fails to compile.
     *
     * - AWS-LC: https://github.com/aws/aws-lc/blob/main/include/openssl/rand.h#L124
     * - OpenSSL: https://github.com/openssl/openssl/blob/master/include/openssl/rand.h#L42
     */
    RAND_METHOD s2n_noop_rand_method = {
        .seed = NULL,
        .bytes = s2n_noop_rand,
        .cleanup = NULL,
        .add = NULL,
        .pseudorand = s2n_noop_rand,
        .status = NULL
    };

    return 0;
}
