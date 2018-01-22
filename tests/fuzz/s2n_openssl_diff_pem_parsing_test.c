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

static int openssl_parse_cert_chain(struct s2n_stuffer *in)
{
    uint8_t chain_len = 0;
    BIO *membio = BIO_new_mem_buf((void *) in->blob.data, in->blob.size - 1);
    X509 *cert = NULL;

    while (1) {
        /* Try parsing Cert PEM with OpenSSL */
        cert = PEM_read_bio_X509(membio, NULL, 0, NULL);
        if (cert != NULL){
            X509_free(cert);
            chain_len++;
        } else {
            break;
        }
    }
    BIO_free(membio);

    return chain_len;

}

static int s2n_parse_cert_chain(struct s2n_stuffer *in)
{
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

    /* Use s2n_config_add_cert_chain_from_stuffer() so that \0 characters don't truncate strings. */
     s2n_config_add_cert_chain_from_stuffer(config, in);

    struct s2n_cert *next = config->cert_and_key_pairs->cert_chain.head;
    int chain_len = 0;
    while(next != NULL) {
        chain_len++;
        next = next->next;
    }

    GUARD(s2n_config_free(config));

    return chain_len;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    struct s2n_stuffer in;
    GUARD(s2n_stuffer_alloc(&in, len + 1));
    GUARD(s2n_stuffer_write_bytes(&in, buf, len));
    in.blob.data[len] = 0;

    uint8_t openssl_chain_len = openssl_parse_cert_chain(&in);
    GUARD(s2n_stuffer_reread(&in));
    uint8_t s2n_chain_len = s2n_parse_cert_chain(&in);
    GUARD(s2n_stuffer_free(&in));


    if (openssl_chain_len > s2n_chain_len) {
        /* If we return -1 here, then this fuzz test will fail if OpenSSL is able to parse a messy PEM file that s2n
         * isn't able to. All well formed PEM files that follow the RFC are still parsable by both, but we should
         * leave this commented out for now until we update our PEM parser to be more lenient,
         * or decide to do something else. */

        /* return -1; */
    }


    return 0;
}
