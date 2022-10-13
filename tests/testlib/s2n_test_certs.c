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

int s2n_read_test_pem(const char *pem_path, char *pem_out, long int max_size)
{
    uint32_t pem_len = 0;

    POSIX_GUARD(s2n_read_test_pem_and_len(pem_path, (uint8_t *)pem_out, &pem_len, max_size - 1));
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

S2N_RESULT s2n_test_cert_chain_from_pem(const char *pem_data, uint8_t protocol_version,
        struct s2n_stuffer *cert_chain_stuffer) {
    RESULT_ENSURE_REF(cert_chain_stuffer);
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(cert_chain_stuffer, 4096));

    DEFER_CLEANUP(struct s2n_stuffer pem_data_stuffer = { 0 }, s2n_stuffer_free);
    RESULT_GUARD_POSIX(s2n_stuffer_alloc_ro_from_string(&pem_data_stuffer, pem_data));

    DEFER_CLEANUP(struct s2n_stuffer cert_stuffer = { 0 }, s2n_stuffer_free);
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&cert_stuffer, 4096));

    while (s2n_stuffer_data_available(&pem_data_stuffer)) {
        RESULT_GUARD_POSIX(s2n_stuffer_certificate_from_pem(&pem_data_stuffer, &cert_stuffer));
        uint32_t cert_len = s2n_stuffer_data_available(&cert_stuffer);
        RESULT_ENSURE_GT(cert_len, 0);

        uint8_t *raw_cert_data = s2n_stuffer_raw_read(&cert_stuffer, cert_len);
        RESULT_ENSURE_REF(raw_cert_data);

        RESULT_GUARD_POSIX(s2n_stuffer_write_uint24(cert_chain_stuffer, cert_len));
        RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(cert_chain_stuffer, raw_cert_data, cert_len));

        /* Add an extra uint8_t to represent 0 length certificate extensions in tls13 */
        if (protocol_version >= S2N_TLS13) {
            RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(cert_chain_stuffer, 0));
        }
    }

    RESULT_ENSURE_GT(s2n_stuffer_data_available(cert_chain_stuffer), 0);

    return S2N_RESULT_OK;
}
