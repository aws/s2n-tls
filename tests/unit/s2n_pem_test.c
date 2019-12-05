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

#include "s2n_test.h"

#include <stdlib.h>
#include <stdio.h>

#include <s2n.h>

#include "utils/s2n_safety.h"
#include "testlib/s2n_testlib.h"

static const char *valid_pem_pairs[][2] = {
    { S2N_RSA_2048_PKCS8_CERT_CHAIN,          S2N_RSA_2048_PKCS8_KEY },
    { S2N_RSA_2048_PKCS1_CERT_CHAIN,          S2N_RSA_2048_PKCS1_KEY },
    { S2N_RSA_2048_PKCS1_LEAF_CERT,           S2N_RSA_2048_PKCS1_KEY },
    { S2N_RSA_CERT_CHAIN_CRLF,                S2N_RSA_KEY_CRLF       },
    /* PEMs with no-op data before/after entries are still valid */
    { S2N_LEAF_WHITESPACE_CERT_CHAIN,         S2N_RSA_2048_PKCS1_KEY },
    { S2N_INTERMEDIATE_WHITESPACE_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY },
    { S2N_ROOT_WHITESPACE_CERT_CHAIN,         S2N_RSA_2048_PKCS1_KEY },
    { S2N_TRAILING_WHITESPACE_CERT_CHAIN,     S2N_RSA_2048_PKCS1_KEY },
    { S2N_LEADING_COMMENT_TEXT_CERT_CHAIN,    S2N_RSA_2048_PKCS1_KEY },
    { S2N_LONG_BASE64_LINES_CERT_CHAIN,       S2N_RSA_2048_PKCS1_KEY },
    { S2N_MISSING_LINE_ENDINGS_CERT_CHAIN,    S2N_RSA_2048_PKCS1_KEY },

    /* Technically Invalid according to RFC, but that we are lenient towards */
    { S2N_INVALID_HEADER_CERT_CHAIN,          S2N_RSA_2048_PKCS1_KEY  },
    { S2N_INVALID_TRAILER_CERT_CHAIN,         S2N_RSA_2048_PKCS1_KEY  },
    { S2N_RSA_2048_PKCS1_CERT_CHAIN,          S2N_INVALID_TRAILER_KEY },
    { S2N_WEIRD_DASHES_CERT_CHAIN,            S2N_RSA_2048_PKCS1_KEY  },
};

static const char *invalid_pem_pairs[][2] = {
    /* Invalid cert PEMs and valid key PEMs */
    { S2N_UNKNOWN_KEYWORD_CERT_CHAIN,         S2N_RSA_2048_PKCS1_KEY  },
    /* Valid cert PEMs and invalid key PEMs */
    { S2N_RSA_2048_PKCS1_CERT_CHAIN,          S2N_INVALID_HEADER_KEY  },
    { S2N_RSA_2048_PKCS1_CERT_CHAIN,          S2N_UNKNOWN_KEYWORD_KEY },
    /* For good measure an invalid cert and invalid key */
    { S2N_UNKNOWN_KEYWORD_CERT_CHAIN,         S2N_UNKNOWN_KEYWORD_KEY },
    { S2N_NO_DASHES_CERT_CHAIN,               S2N_RSA_2048_PKCS1_KEY  },
};

int main(int argc, char **argv)
{
    struct s2n_config *config;
    char *cert_chain_pem;
    char *private_key_pem;
    struct s2n_cert_chain_and_key *chain_and_key;

    BEGIN_TEST();
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

    for (int i = 0; i < s2n_array_len(valid_pem_pairs); i++) {
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(valid_pem_pairs[i][0], cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(valid_pem_pairs[i][1], private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    for (int i = 0; i < s2n_array_len(invalid_pem_pairs); i++) {
        EXPECT_SUCCESS(s2n_read_test_pem(invalid_pem_pairs[i][0], cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(invalid_pem_pairs[i][1], private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_FAILURE(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    }

    free(cert_chain_pem);
    free(private_key_pem);
    END_TEST();
}
