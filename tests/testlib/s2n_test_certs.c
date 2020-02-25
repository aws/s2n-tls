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
#include <stdint.h>

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

#include "testlib/s2n_testlib.h"

int s2n_test_cert_chain_and_key_new(struct s2n_cert_chain_and_key **chain_and_key,
        const char *cert_chain_file, const char *prviate_key_file)
{
    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
    char private_key_pem[S2N_MAX_TEST_PEM_SIZE];

    GUARD(s2n_read_test_pem(cert_chain_file, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    GUARD(s2n_read_test_pem(prviate_key_file, private_key_pem, S2N_MAX_TEST_PEM_SIZE));

    notnull_check(*chain_and_key = s2n_cert_chain_and_key_new());
    GUARD(s2n_cert_chain_and_key_load_pem(*chain_and_key, cert_chain_pem, private_key_pem));

    return S2N_SUCCESS;
}

int s2n_read_test_pem(const char *pem_path, char *pem_out, long int max_size)
{
    FILE *pem_file = fopen(pem_path, "rb");
    if (!pem_file) {
        S2N_ERROR(S2N_ERR_NULL);
    }

    /* Make sure we can fit the pem into the output buffer */
    fseek(pem_file, 0, SEEK_END);
    const long int pem_file_size = ftell(pem_file);
    /* one extra for the null byte */
    rewind(pem_file);

    if (max_size < (pem_file_size + 1)) {
        S2N_ERROR(S2N_ERR_NOMEM);
    }

    if (fread(pem_out, sizeof(char), pem_file_size, pem_file) < pem_file_size) {
        S2N_ERROR(S2N_ERR_IO);
    }

    pem_out[pem_file_size] = '\0';
    fclose(pem_file);

    return 0;
}

