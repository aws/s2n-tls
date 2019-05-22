/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "s2n_test.h"

#define MAX_TOKENS 256

static void s2n_fuzz_atexit()
{
    s2n_cleanup();
}

int LLVMFuzzerInitialize(const uint8_t *buf, size_t len)
{
#ifdef S2N_TEST_IN_FIPS_MODE
    S2N_TEST_ENTER_FIPS_MODE();
#endif

    GUARD(s2n_init());
    GUARD(atexit(s2n_fuzz_atexit));
    return 0;
}

/*
 * Tokenize the input fuzz buffer based on NULL bytes into output array and return the number of tokens.
 * Avoiding extra heap allocation here to increase fuzz test rate.
 */
size_t find_strings(const uint8_t *buf, size_t len, const char **output_strings, size_t max_strings)
{
    size_t num_strings = 0;
    int cursor = 0;
    while(1) {
        if (cursor >= len || num_strings == max_strings) {
            return num_strings;
        }
        const char *cur_str = (const char *) (buf + cursor);
        const char *next_null = (const char *) memchr((const void *) cur_str, '\0', (len - cursor));
        if (next_null == NULL) {
            return num_strings;
        }

        /* We found a null byte. Move the cursor beyond it. */
        cursor = (((const uint8_t *) next_null - buf) + 1);
        if (cursor >= len) {
            return num_strings;
        }
        output_strings[num_strings] = cur_str;
        num_strings++;
    }
}

GENERAL_NAME *string_to_general_name(const char *str)
{
    ASN1_IA5STRING *asn1_name_str = ASN1_IA5STRING_new();
    if (!asn1_name_str) {
        return NULL;
    }

    if (!ASN1_STRING_set(asn1_name_str, str, strlen(str))) {
        ASN1_IA5STRING_free(asn1_name_str);
        return NULL;
    }

    GENERAL_NAME *san_name = GENERAL_NAME_new();
    if (!san_name) {
        ASN1_IA5STRING_free(asn1_name_str);
        return NULL;
    }

    GENERAL_NAME_set0_value(san_name, GEN_DNS, asn1_name_str);
    return san_name;
}

static int set_x509_sans(X509* x509_cert, GENERAL_NAMES *san_names)
{
    if (X509_add1_ext_i2d(x509_cert, NID_subject_alt_name, san_names, 0, X509V3_ADD_REPLACE) <= 0) {
        return -1;
    }

    return 0;
}

static int set_x509_cns(X509 *x509_cert, const unsigned char **cns, size_t num_cns)
{
    X509_NAME *x509_name = X509_NAME_new();
    if (!x509_name) {
        return -1;
    }

    for (int i = 0; i < num_cns; i++) {
        X509_NAME_add_entry_by_NID(x509_name, NID_commonName, MBSTRING_ASC, (unsigned char *)(uintptr_t) cns[i], -1, -1, 1);
    }

    X509_set_subject_name(x509_cert, x509_name);
    X509_NAME_free(x509_name);
    return 0;
}

/*
 * This fuzz test uses the fuzz input to:
 * - Generate the data to populate in the SAN of a certificate
 * - Generate the data to populate the SNI TLS extension
 * - Fuzz the certificate matching function in s2n: s2n_cert_chain_and_key_matches_name
 */
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    struct s2n_cert_chain_and_key *cert = s2n_cert_chain_and_key_new();
    struct s2n_config *config = s2n_config_new();
    struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
    GENERAL_NAMES* san_names = sk_GENERAL_NAME_new_null();
    X509 *x509_cert = X509_new();

    if (!x509_cert || !san_names || !cert || !config || !conn) {
        goto cleanup;
    }

    /* Create an array of strings based on fuzz input. To populate the cert SANs,CN and
     * input hostname.
     */
    const char *strings[MAX_TOKENS] = { NULL };
    size_t num_strings = find_strings(buf, len, strings, MAX_TOKENS);
    size_t num_sans = num_strings/2 ;
    size_t num_cns = (num_strings == 1) ? 1 : num_sans;
    const unsigned char **cns = (const unsigned char **) (&strings[num_sans]);

    for (int i = 0; i < num_sans; i++) {
        GENERAL_NAME *san_name = string_to_general_name(strings[i]);
        if (!san_name) {
            continue;
        }
        sk_GENERAL_NAME_push(san_names, san_name);
    }

    if (num_sans != 0 && set_x509_sans(x509_cert, san_names) < 0) {
        goto cleanup;
    }
    if (num_cns != 0 && set_x509_cns(x509_cert, (const unsigned char **) cns, num_cns) < 0) {
        goto cleanup;
    }

    /* We've created an X509 object with names. Pass it back to s2n to parse and load. */
    if (s2n_cert_chain_and_key_load_cns(cert, x509_cert) < 0) {
        goto cleanup;
    }

    if (s2n_cert_chain_and_key_load_sans(cert, x509_cert) < 0) {
        goto cleanup;
    }

    if (s2n_connection_set_config(conn, config) < 0) {
        goto cleanup;
    }

    if (s2n_config_add_cert_chain_and_key_to_store(config, cert) < 0) {
        goto cleanup;
    }

    /* Cert selection relies on this being set and we haven't added a "real" public/private key to the cert.
     * Set the type based on fuzz input.
     */
    s2n_cert_type cert_type = (len % 2) ? S2N_CERT_TYPE_RSA_SIGN : S2N_CERT_TYPE_ECDSA_SIGN;
    struct s2n_cert head = { .cert_type = cert_type };
    cert->cert_chain->head = &head;

    /* Not checking the return value as we aren't using this fuzz test for matching correctness. */
    for (int i = 0; i < num_strings; i++) {
        strncpy(conn->server_name, strings[i], S2N_MAX_SERVER_NAME);
        /* Not checking the return value as we aren't using this fuzz test for matching correctness. */
        s2n_conn_find_name_matching_certs(conn);
    }
    cert->cert_chain->head = NULL;
cleanup:
    if (x509_cert != NULL) { X509_free(x509_cert); }
    if (san_names != NULL) { GENERAL_NAMES_free(san_names); }
    if (cert != NULL) { s2n_cert_chain_and_key_free(cert); }
    if (conn != NULL) { s2n_connection_free(conn); }
    if (config != NULL) { s2n_config_free(config); }

    return 0;
}
