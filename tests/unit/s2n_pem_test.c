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

#include <stdio.h>
#include <stdlib.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_safety.h"

/* The ECDSA private key is missing the "publicKey" field, which is optional.
 * The missing field makes the cert type difficult to detect via ASN1 parsing */
#define S2N_MISSING_ECDSA_PUB_CERT_KEY        "../pems/missing_public_key_ecdsa_key.pem"
#define S2N_MISSING_ECDSA_PUB_CERT_CERT_CHAIN "../pems/missing_public_key_ecdsa_cert.pem"

static const char *valid_pem_pairs[][2] = {
    { S2N_RSA_2048_PKCS8_CERT_CHAIN, S2N_RSA_2048_PKCS8_KEY },
    { S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
    { S2N_RSA_2048_PKCS1_LEAF_CERT, S2N_RSA_2048_PKCS1_KEY },
    { S2N_RSA_CERT_CHAIN_CRLF, S2N_RSA_KEY_CRLF },
    /* PEMs with no-op data before/after entries are still valid */
    { S2N_LEAF_WHITESPACE_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
    { S2N_INTERMEDIATE_WHITESPACE_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
    { S2N_ROOT_WHITESPACE_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
    { S2N_TRAILING_WHITESPACE_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
    { S2N_LEADING_COMMENT_TEXT_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
    { S2N_LONG_BASE64_LINES_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
    { S2N_MISSING_LINE_ENDINGS_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
    { S2N_MISSING_ECDSA_PUB_CERT_CERT_CHAIN, S2N_MISSING_ECDSA_PUB_CERT_KEY },

    /* Technically Invalid according to RFC, but that we are lenient towards */
    { S2N_INVALID_HEADER_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
    { S2N_INVALID_TRAILER_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
    { S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_INVALID_TRAILER_KEY },
    { S2N_WEIRD_DASHES_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
};

static const char *invalid_pem_pairs[][2] = {
    /* Invalid cert PEMs and valid key PEMs */
    { S2N_UNKNOWN_KEYWORD_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
    /* Valid cert PEMs and invalid key PEMs */
    { S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_INVALID_HEADER_KEY },
    { S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_UNKNOWN_KEYWORD_KEY },
    /* For good measure an invalid cert and invalid key */
    { S2N_UNKNOWN_KEYWORD_CERT_CHAIN, S2N_UNKNOWN_KEYWORD_KEY },
    { S2N_NO_DASHES_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
};

const struct {
    const char *path;
    uint16_t length;
} valid_cert_chains[] = {
    { .path = S2N_TEST_TRUST_STORE, .length = 179 },
};

int main(int argc, char **argv)
{
    struct s2n_config *config = NULL;
    char *cert_chain_pem = NULL;
    char *private_key_pem = NULL;
    struct s2n_cert_chain_and_key *chain_and_key = NULL;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

    for (size_t i = 0; i < s2n_array_len(valid_pem_pairs); i++) {
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(valid_pem_pairs[i][0], cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(valid_pem_pairs[i][1], private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    for (size_t i = 0; i < s2n_array_len(invalid_pem_pairs); i++) {
        EXPECT_SUCCESS(s2n_read_test_pem(invalid_pem_pairs[i][0], cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(invalid_pem_pairs[i][1], private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_FAILURE(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    }

    char large_cert_chain_pem[500000] = { 0 };
    for (size_t i = 0; i < s2n_array_len(valid_cert_chains); i++) {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_NOT_NULL(chain);
        EXPECT_SUCCESS(s2n_read_test_pem(valid_cert_chains[i].path,
                large_cert_chain_pem, sizeof(large_cert_chain_pem)));

        uint32_t length = 0;
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_public_pem_bytes(chain,
                (uint8_t *) large_cert_chain_pem, strlen(large_cert_chain_pem)));
        EXPECT_SUCCESS(s2n_cert_chain_get_length(chain, &length));
        EXPECT_EQUAL(length, valid_cert_chains[i].length);

        DEFER_CLEANUP(struct s2n_config *test_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(test_config);
        EXPECT_SUCCESS(s2n_config_add_pem_to_trust_store(test_config, large_cert_chain_pem));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(test_config, chain));
    }

    free(cert_chain_pem);
    free(private_key_pem);
    END_TEST();
}
