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

#include <stdint.h>
#include <stdio.h>

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_safety.h"

int s2n_test_cert_chain_and_key_new(struct s2n_cert_chain_and_key **chain_and_key,
        const char *cert_chain_file, const char *private_key_file)
{
    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
    char private_key_pem[S2N_MAX_TEST_PEM_SIZE];

    POSIX_GUARD(s2n_read_test_pem(cert_chain_file, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    POSIX_GUARD(s2n_read_test_pem(private_key_file, private_key_pem, S2N_MAX_TEST_PEM_SIZE));

    POSIX_GUARD_PTR(*chain_and_key = s2n_cert_chain_and_key_new());
    POSIX_GUARD(s2n_cert_chain_and_key_load_pem(*chain_and_key, cert_chain_pem, private_key_pem));

    return S2N_SUCCESS;
}

int s2n_test_cert_permutation_load_server_chain(struct s2n_cert_chain_and_key **chain_and_key,
        const char *type, const char *signature, const char *size, const char *digest)
{
    char path_buffer[S2N_MAX_TEST_PEM_PATH_LENGTH];

    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
    char private_key_pem[S2N_MAX_TEST_PEM_SIZE];

    sprintf(path_buffer, "../pems/permutations/%s_%s_%s_%s/server-chain.pem", type, signature, size, digest);
    POSIX_GUARD(s2n_read_test_pem(path_buffer, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));

    sprintf(path_buffer, "../pems/permutations/%s_%s_%s_%s/server-key.pem", type, signature, size, digest);
    POSIX_GUARD(s2n_read_test_pem(path_buffer, private_key_pem, S2N_MAX_TEST_PEM_SIZE));

    POSIX_GUARD_PTR(*chain_and_key = s2n_cert_chain_and_key_new());
    POSIX_GUARD(s2n_cert_chain_and_key_load_pem(*chain_and_key, cert_chain_pem, private_key_pem));

    return S2N_SUCCESS;
}

int s2n_test_cert_permutation_get_ca_path(char *output, const char *type, const char *signature,
        const char *size, const char *digest)
{
    sprintf(output, "../pems/permutations/%s_%s_%s_%s/ca-cert.pem", type, signature, size, digest);
    return S2N_SUCCESS;
}

S2N_RESULT s2n_test_cert_permutation_get_server_chain_path(char *output, const char *type,
        const char *signature, const char *size, const char *digest)
{
    sprintf(output, "../pems/permutations/%s_%s_%s_%s/server-chain.pem", type, signature, size,
            digest);
    return S2N_RESULT_OK;
}

int s2n_read_test_pem(const char *pem_path, char *pem_out, long int max_size)
{
    uint32_t pem_len = 0;

    POSIX_GUARD(s2n_read_test_pem_and_len(pem_path, (uint8_t *) pem_out, &pem_len, max_size - 1));
    pem_out[pem_len] = '\0';

    return 0;
}

int s2n_read_test_pem_and_len(const char *pem_path, uint8_t *pem_out, uint32_t *pem_len, long int max_size)
{
    FILE *pem_file = fopen(pem_path, "rb");
    if (!pem_file) {
        POSIX_BAIL(S2N_ERR_NULL);
    }

    /* Make sure we can fit the pem into the output buffer */
    fseek(pem_file, 0, SEEK_END);
    const long int pem_file_size = ftell(pem_file);
    /* one extra for the null byte */
    rewind(pem_file);

    if (max_size < (pem_file_size)) {
        POSIX_BAIL(S2N_ERR_NOMEM);
    }

    if (fread(pem_out, sizeof(char), pem_file_size, pem_file) < pem_file_size) {
        POSIX_BAIL(S2N_ERR_IO);
    }

    *pem_len = pem_file_size;
    fclose(pem_file);

    return 0;
}

S2N_RESULT s2n_test_cert_chain_data_from_pem(struct s2n_connection *conn, const char *pem_path,
        struct s2n_stuffer *cert_chain_stuffer)
{
    RESULT_ENSURE_REF(cert_chain_stuffer);

    uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    uint32_t cert_chain_pem_len = 0;
    RESULT_GUARD_POSIX(s2n_read_test_pem_and_len(pem_path, cert_chain_pem, &cert_chain_pem_len, S2N_MAX_TEST_PEM_SIZE));

    RESULT_GUARD(s2n_test_cert_chain_data_from_pem_data(conn, cert_chain_pem, cert_chain_pem_len, cert_chain_stuffer));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_cert_chain_data_from_pem_data(struct s2n_connection *conn, uint8_t *pem_data, uint32_t pem_data_len,
        struct s2n_stuffer *cert_chain_stuffer)
{
    DEFER_CLEANUP(struct s2n_stuffer certificate_message_stuffer = { 0 }, s2n_stuffer_free);
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&certificate_message_stuffer, 4096));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new(),
            s2n_cert_chain_and_key_ptr_free);
    RESULT_GUARD_POSIX(s2n_cert_chain_and_key_load_public_pem_bytes(chain_and_key, pem_data, pem_data_len));

    RESULT_GUARD_POSIX(s2n_send_cert_chain(conn, &certificate_message_stuffer, chain_and_key));

    /* Skip the cert chain length */
    RESULT_GUARD_POSIX(s2n_stuffer_skip_read(&certificate_message_stuffer, 3));

    uint32_t cert_chain_len = s2n_stuffer_data_available(&certificate_message_stuffer);
    RESULT_GUARD_POSIX(s2n_stuffer_alloc(cert_chain_stuffer, cert_chain_len));
    RESULT_GUARD_POSIX(s2n_stuffer_copy(&certificate_message_stuffer, cert_chain_stuffer, cert_chain_len));

    return S2N_RESULT_OK;
}
