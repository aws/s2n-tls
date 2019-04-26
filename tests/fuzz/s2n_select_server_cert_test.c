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

/*
 * This fuzz test uses the fuzz input to:
 * - Generate the data to populate in the SAN of a certificate
 * - Generate the data to populate the SNI TLS extension
 * - Fuzz the certificate matching function in s2n: s2n_cert_chain_and_key_matches_name
 */
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    struct s2n_cert_chain_and_key *cert = s2n_cert_chain_and_key_new();
    GENERAL_NAMES* san_names = sk_GENERAL_NAME_new_null();
    X509 *x509_cert = X509_new();

    if (!x509_cert || !san_names || !cert) {
        goto cleanup;
    }

    /* Create an array of strings based on fuzz input. To populate the cert SANs and
     * input hostname.
     */
    const char *strings[MAX_TOKENS] = { NULL };
    size_t num_strings = find_strings(buf, len, strings, MAX_TOKENS);
    size_t num_sans;
    /* This should be a match since we make the hostname the same string as a SAN we've added.
     * It won't be a match when the SAN is longer than domain name length for SNI.
     */
    const char *likely_matching_hostname;
    /* A string that was not part of the set of strings we added for SANs. */
    const char *other_hostname = NULL;
    if (num_strings == 0) {
        likely_matching_hostname = "";
        num_sans = 0;
    } else {
        num_sans = num_strings - 1;
        likely_matching_hostname = strings[0];
        other_hostname = strings[num_strings - 1];
    }

    for (int i = 0; i < num_sans; i++) {
        GENERAL_NAME *san_name = string_to_general_name(strings[i]);
        if (!san_name) {
            continue;
        }
        sk_GENERAL_NAME_push(san_names, san_name);
    }

    if (X509_add1_ext_i2d(x509_cert, NID_subject_alt_name, san_names, 0, X509V3_ADD_REPLACE) <= 0) {
        goto cleanup;
    }

    cert->x509_cert = x509_cert;
    cert->san_names = san_names;

    /* Not checking the return value as we aren't using this fuzz test for matching correctness. */
    s2n_cert_chain_and_key_matches_name(cert, likely_matching_hostname);
    if (other_hostname != NULL) {
        s2n_cert_chain_and_key_matches_name(cert, other_hostname);
    }

    cert->x509_cert = NULL;
    cert->san_names = NULL;
cleanup:
    if (x509_cert != NULL) { X509_free(x509_cert); }
    if (san_names != NULL) { GENERAL_NAMES_free(san_names); }
    if (cert != NULL) { s2n_cert_chain_and_key_free(cert); }

    return 0;
}
