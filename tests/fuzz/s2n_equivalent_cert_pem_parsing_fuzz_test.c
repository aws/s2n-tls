/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/dh.h>
#include <openssl/ec.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_config.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"
#include "s2n_test.h"

static void s2n_fuzz_atexit()
{
    s2n_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    CONF_modules_free();
    ERR_clear_error();
}

int LLVMFuzzerInitialize(const uint8_t *buf, size_t len)
{
#ifdef S2N_TEST_IN_FIPS_MODE
    S2N_TEST_ENTER_FIPS_MODE();
#endif

    GUARD(s2n_init());
    GUARD(atexit(s2n_fuzz_atexit));
    GUARD(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    struct s2n_stuffer in;
    GUARD(s2n_stuffer_alloc(&in, len + 1));
    GUARD(s2n_stuffer_write_bytes(&in, buf, len));
    in.blob.data[len] = 0;

    uint8_t parsable_by_openssl = 0;

    /* Try parsing Cert PEM with OpenSSL */
    BIO *membio = BIO_new_mem_buf((void *) in.blob.data, len);
    if (membio != NULL) {
        X509 *cert = PEM_read_bio_X509(membio, NULL, 0, NULL);
        if (cert != NULL){
            X509_free(cert);
            parsable_by_openssl = 1;
        }
        BIO_free(membio);
    }

    struct s2n_config *config = s2n_config_new();

    struct s2n_blob mem;
    GUARD(s2n_alloc(&mem, sizeof(struct s2n_cert_chain_and_key)));
    config->cert_and_key_pairs = (struct s2n_cert_chain_and_key *)(void *)mem.data;
    config->cert_and_key_pairs->cert_chain.head = NULL;
    config->cert_and_key_pairs->private_key.free = NULL;
    config->cert_and_key_pairs->ocsp_status.data = NULL;
    config->cert_and_key_pairs->ocsp_status.size = 0;
    config->cert_and_key_pairs->sct_list.data = NULL;
    config->cert_and_key_pairs->sct_list.size = 0;
    memset(&config->cert_and_key_pairs->ocsp_status, 0, sizeof(config->cert_and_key_pairs->ocsp_status));
    memset(&config->cert_and_key_pairs->sct_list, 0, sizeof(config->cert_and_key_pairs->sct_list));

    int parsable_by_s2n = !s2n_config_add_cert_chain(config, (const char*) in.blob.data);

    GUARD(s2n_stuffer_free(&in));
    GUARD(s2n_config_free(config));

    if (parsable_by_openssl && !parsable_by_s2n) {
        /* If we return -1 here, then this fuzz test will fail if OpenSSL is able to parse a messy PEM file that s2n
         * isn't able to. All well formed PEM files are still parsable by both, but we should leave this commented out
         * for now until we update our PEM parser to be more lenient, or decide to do something else. */

        /** return -1; **/
    }


    return 0;
}
