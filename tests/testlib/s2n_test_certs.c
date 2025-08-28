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

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include "crypto/s2n_libcrypto.h"
#include "crypto/s2n_mldsa.h"
#include "crypto/s2n_rsa_pss.h"
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_safety.h"

#define S2N_TEST_CERT_CHAIN_LIST_MAX         19
#define S2N_TEST_CERT_CHAIN_LIST_MAX_SKIPPED 5

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

S2N_RESULT s2n_test_cert_permutation_load_server_chain_from_name(
        struct s2n_cert_chain_and_key **chain_and_key, const char *name)
{
    char path_buffer[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };

    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    snprintf(path_buffer, S2N_MAX_TEST_PEM_PATH_LENGTH,
            "../pems/permutations/%s/server-chain.pem", name);
    RESULT_GUARD_POSIX(s2n_read_test_pem(path_buffer, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));

    char private_key_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    snprintf(path_buffer, S2N_MAX_TEST_PEM_PATH_LENGTH,
            "../pems/permutations/%s/server-key.pem", name);
    RESULT_GUARD_POSIX(s2n_read_test_pem(path_buffer, private_key_pem, S2N_MAX_TEST_PEM_SIZE));

    RESULT_GUARD_PTR(*chain_and_key = s2n_cert_chain_and_key_new());
    RESULT_GUARD_POSIX(s2n_cert_chain_and_key_load_pem(*chain_and_key, cert_chain_pem, private_key_pem));

    return S2N_RESULT_OK;
}

int s2n_test_cert_permutation_load_server_chain(struct s2n_cert_chain_and_key **chain_and_key,
        const char *type, const char *signature, const char *size, const char *digest)
{
    char name_buffer[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
    snprintf(name_buffer, S2N_MAX_TEST_PEM_PATH_LENGTH,
            "%s_%s_%s_%s", type, signature, size, digest);
    POSIX_GUARD_RESULT(s2n_test_cert_permutation_load_server_chain_from_name(chain_and_key, name_buffer));
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

S2N_RESULT s2n_test_cert_chains_init(struct s2n_test_cert_chain_list *chains)
{
    /* Load all permutations */
    {
        DIR *root = opendir("../pems/permutations");
        RESULT_ENSURE_REF(root);
        struct dirent *dir = NULL;
        while ((dir = readdir(root)) != NULL) {
            /* Skip ., .., the README, etc.
             * This is pretty hacky: we can switch to stat later if necessary.
-            */
            if (strchr(dir->d_name, '_') == NULL) {
                continue;
            }
            if (!s2n_is_rsa_pss_certs_supported() && strstr(dir->d_name, "pss")) {
                chains->skipped++;
                continue;
            }
            if (s2n_libcrypto_is_openssl_fips() && strstr(dir->d_name, "rsae_pkcs_1024_sha1")) {
                chains->skipped++;
                continue;
            }

            RESULT_ENSURE_LT(chains->count, S2N_MAX_TEST_CERT_CHAINS);
            struct s2n_test_cert_chain_entry *entry = &chains->chains[chains->count];

            RESULT_GUARD(s2n_test_cert_permutation_load_server_chain_from_name(
                    &entry->chain, dir->d_name));
            chains->count++;
        }
        closedir(root);
    }

    /* Load all MLDSA test certs.
     * MLDSA is not yet included in permutations due to difficulties generating MLDSA certs.
     * We instead continue to test with the example certs from the RFC.
     */
    const char *mldsa_names[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
    if (s2n_mldsa_is_supported()) {
        for (size_t i = 0; i < s2n_array_len(mldsa_names); i++) {
            RESULT_ENSURE_LT(chains->count, S2N_MAX_TEST_CERT_CHAINS);
            struct s2n_test_cert_chain_entry *entry = &chains->chains[chains->count];

            char path_buffer[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };

            char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            snprintf(path_buffer, S2N_MAX_TEST_PEM_PATH_LENGTH,
                    "../pems/mldsa/%s.crt", mldsa_names[i]);
            RESULT_GUARD_POSIX(s2n_read_test_pem(path_buffer, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));

            char private_key_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            snprintf(path_buffer, S2N_MAX_TEST_PEM_PATH_LENGTH,
                    "../pems/mldsa/%s-seed.priv", mldsa_names[i]);
            RESULT_GUARD_POSIX(s2n_read_test_pem(path_buffer, private_key_pem, S2N_MAX_TEST_PEM_SIZE));

            entry->chain = s2n_cert_chain_and_key_new();
            RESULT_GUARD_POSIX(s2n_cert_chain_and_key_load_pem(
                    entry->chain, cert_chain_pem, private_key_pem));

            chains->count++;
        }
    } else {
        chains->skipped += s2n_array_len(mldsa_names);
    }

    /* Sanity check result */
    RESULT_ENSURE_LTE(chains->skipped, S2N_TEST_CERT_CHAIN_LIST_MAX_SKIPPED);
    RESULT_ENSURE_EQ(chains->skipped + chains->count, S2N_TEST_CERT_CHAIN_LIST_MAX);

    return S2N_RESULT_OK;
}

/*
 * Sets "supported" to a specific value for all chains of a given pkey_type.
 * "supported" could indicate an index in an array of policies (as in s2n_security_policies_test),
 * or could indicate a specific policy version, or could simply indicate true/false.
 * The meaning of the value depends on the structure of the test.
 */
S2N_RESULT s2n_test_cert_chains_set_supported(struct s2n_test_cert_chain_list *chains,
        s2n_pkey_type target_type, uint64_t supported)
{
    for (size_t i = 0; i < chains->count; i++) {
        struct s2n_test_cert_chain_entry *entry = &chains->chains[i];
        s2n_pkey_type entry_type = entry->chain->cert_chain->head->pkey_type;
        if (entry_type == target_type) {
            entry->supported = supported;
        }
    }
    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_test_cert_chains_free(struct s2n_test_cert_chain_list *chains)
{
    for (size_t i = 0; i < chains->count; i++) {
        struct s2n_test_cert_chain_entry *entry = &chains->chains[i];
        RESULT_GUARD_POSIX(s2n_cert_chain_and_key_free(entry->chain));
        entry->supported = 0;
    }
    chains->count = 0;
    return S2N_RESULT_OK;
}
