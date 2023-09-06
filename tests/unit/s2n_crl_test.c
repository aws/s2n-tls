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

#include "tls/s2n_crl.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#define S2N_CRL_ROOT_CERT                            "../pems/crl/root_cert.pem"
#define S2N_CRL_NONE_REVOKED_CERT_CHAIN              "../pems/crl/none_revoked_cert_chain.pem"
#define S2N_CRL_NONE_REVOKED_KEY                     "../pems/crl/none_revoked_key.pem"
#define S2N_CRL_INTERMEDIATE_REVOKED_CERT_CHAIN      "../pems/crl/intermediate_revoked_cert_chain.pem"
#define S2N_CRL_INTERMEDIATE_REVOKED_KEY             "../pems/crl/intermediate_revoked_key.pem"
#define S2N_CRL_LEAF_REVOKED_CERT_CHAIN              "../pems/crl/leaf_revoked_cert_chain.pem"
#define S2N_CRL_LEAF_REVOKED_KEY                     "../pems/crl/leaf_revoked_key.pem"
#define S2N_CRL_ALL_REVOKED_CERT_CHAIN               "../pems/crl/all_revoked_cert_chain.pem"
#define S2N_CRL_ALL_REVOKED_KEY                      "../pems/crl/all_revoked_key.pem"
#define S2N_CRL_ROOT_CRL                             "../pems/crl/root_crl.pem"
#define S2N_CRL_INTERMEDIATE_CRL                     "../pems/crl/intermediate_crl.pem"
#define S2N_CRL_INTERMEDIATE_REVOKED_CRL             "../pems/crl/intermediate_revoked_crl.pem"
#define S2N_CRL_INTERMEDIATE_INVALID_THIS_UPDATE_CRL "../pems/crl/intermediate_invalid_this_update_crl.pem"
#define S2N_CRL_INTERMEDIATE_INVALID_NEXT_UPDATE_CRL "../pems/crl/intermediate_invalid_next_update_crl.pem"

#define CRL_TEST_CHAIN_LEN 2

struct crl_lookup_data {
    struct s2n_crl *crls[5];
    X509 *certs[5];
    uint8_t callback_invoked_count;
};

static int crl_lookup_test_callback(struct s2n_crl_lookup *lookup, void *context)
{
    struct crl_lookup_data *crl_data = (struct crl_lookup_data *) context;
    crl_data->callback_invoked_count += 1;
    crl_data->certs[lookup->cert_idx] = lookup->cert;

    struct s2n_crl *crl = crl_data->crls[lookup->cert_idx];
    if (crl == NULL) {
        POSIX_GUARD(s2n_crl_lookup_ignore(lookup));
    } else {
        POSIX_GUARD(s2n_crl_lookup_set(lookup, crl));
    }

    return 0;
}

static int crl_lookup_noop(struct s2n_crl_lookup *lookup, void *context)
{
    return 0;
}

static int crl_lookup_callback_fail(struct s2n_crl_lookup *lookup, void *context)
{
    return 1;
}

static uint8_t verify_host_always_allow(const char *host_name, size_t host_name_len, void *data)
{
    return 1;
}

static struct s2n_crl *load_test_crl(const char *pem_path)
{
    uint8_t crl_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    uint32_t pem_len = 0;
    PTR_GUARD_POSIX(s2n_read_test_pem_and_len(pem_path, crl_pem, &pem_len, S2N_MAX_TEST_PEM_SIZE));
    DEFER_CLEANUP(struct s2n_crl *crl = s2n_crl_new(), s2n_crl_free);
    PTR_ENSURE_REF(crl);
    PTR_GUARD_POSIX(s2n_crl_load_pem(crl, crl_pem, pem_len));

    struct s2n_crl *crl_ret = crl;
    ZERO_TO_DISABLE_DEFER_CLEANUP(crl);

    return crl_ret;
}

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    /* s2n_crl_new allocates and frees a s2n_crl */
    {
        struct s2n_crl *crl = s2n_crl_new();
        EXPECT_NOT_NULL(crl);

        EXPECT_SUCCESS(s2n_crl_free(&crl));
        EXPECT_NULL(crl);

        /* Multiple calls to free succeed */
        EXPECT_SUCCESS(s2n_crl_free(&crl));
        EXPECT_NULL(crl);
    };

    /* s2n_crl_new allocates and frees a s2n_crl with an internal X509_CRL set */
    {
        struct s2n_crl *crl = load_test_crl(S2N_CRL_ROOT_CRL);
        EXPECT_NOT_NULL(crl);
        EXPECT_NOT_NULL(crl->crl);

        EXPECT_SUCCESS(s2n_crl_free(&crl));
        EXPECT_NULL(crl);

        /* Multiple calls to free succeed */
        EXPECT_SUCCESS(s2n_crl_free(&crl));
        EXPECT_NULL(crl);
    };

    /* Ensure s2n_crl_load_pem produces a valid X509_CRL internally */
    {
        DEFER_CLEANUP(struct s2n_crl *crl = load_test_crl(S2N_CRL_ROOT_CRL), s2n_crl_free);
        EXPECT_NOT_NULL(crl);
        EXPECT_NOT_NULL(crl->crl);

        /* Make sure an OpenSSL operation succeeds on the internal X509_CRL */
        X509_NAME *crl_name = X509_CRL_get_issuer(crl->crl);
        POSIX_ENSURE_REF(crl_name);
    };

    /* s2n_crl_load_pem fails if provided a bad pem */
    {
        uint8_t crl_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint32_t crl_pem_len = 0;
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_CRL_ROOT_CRL, crl_pem, &crl_pem_len, S2N_MAX_TEST_PEM_SIZE));
        DEFER_CLEANUP(struct s2n_crl *crl = s2n_crl_new(), s2n_crl_free);
        EXPECT_NOT_NULL(crl);
        EXPECT_SUCCESS(s2n_crl_load_pem(crl, crl_pem, crl_pem_len));

        /* Change a random byte in the pem to make it invalid */
        crl_pem[50] = 1;

        DEFER_CLEANUP(struct s2n_crl *invalid_crl = s2n_crl_new(), s2n_crl_free);
        EXPECT_NOT_NULL(invalid_crl);
        EXPECT_FAILURE_WITH_ERRNO(s2n_crl_load_pem(invalid_crl, crl_pem, crl_pem_len),
                S2N_ERR_INVALID_PEM);
    };

    /* CRL issuer hash is retrieved successfully */
    {
        DEFER_CLEANUP(struct s2n_crl *crl = load_test_crl(S2N_CRL_ROOT_CRL), s2n_crl_free);
        EXPECT_NOT_NULL(crl);

        uint64_t hash = 0;
        EXPECT_SUCCESS(s2n_crl_get_issuer_hash(crl, &hash));
        EXPECT_TRUE(hash != 0);
    };

    DEFER_CLEANUP(struct s2n_crl *root_crl = load_test_crl(S2N_CRL_ROOT_CRL), s2n_crl_free);
    EXPECT_NOT_NULL(root_crl);

    DEFER_CLEANUP(struct s2n_crl *intermediate_crl = load_test_crl(S2N_CRL_INTERMEDIATE_CRL), s2n_crl_free);
    EXPECT_NOT_NULL(intermediate_crl);

    DEFER_CLEANUP(struct s2n_crl *intermediate_revoked_crl = load_test_crl(S2N_CRL_INTERMEDIATE_REVOKED_CRL), s2n_crl_free);
    EXPECT_NOT_NULL(intermediate_revoked_crl);

    DEFER_CLEANUP(struct s2n_crl *intermediate_invalid_this_update_crl =
                          load_test_crl(S2N_CRL_INTERMEDIATE_INVALID_THIS_UPDATE_CRL),
            s2n_crl_free);
    EXPECT_NOT_NULL(intermediate_invalid_this_update_crl);

    DEFER_CLEANUP(struct s2n_crl *intermediate_invalid_next_update_crl =
                          load_test_crl(S2N_CRL_INTERMEDIATE_INVALID_NEXT_UPDATE_CRL),
            s2n_crl_free);
    EXPECT_NOT_NULL(intermediate_invalid_next_update_crl);

    /* Save a list of received X509s for s2n_crl_lookup tests */
    struct crl_lookup_data received_lookup_data = { 0 };
    DEFER_CLEANUP(struct s2n_x509_validator received_lookup_data_validator, s2n_x509_validator_wipe);

    /* CRL validation succeeds for unrevoked certificate chain */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        EXPECT_SUCCESS(s2n_x509_validator_init(&received_lookup_data_validator, &trust_store, 0));

        received_lookup_data.crls[0] = intermediate_crl;
        received_lookup_data.crls[1] = root_crl;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, crl_lookup_test_callback, &received_lookup_data));

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_CRL_NONE_REVOKED_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&received_lookup_data_validator, connection, chain_data,
                chain_len, &pkey_type, &public_key_out));
        EXPECT_TRUE(received_lookup_data.callback_invoked_count == CRL_TEST_CHAIN_LEN);

        /* Ensure all certificates were received in the callback */
        for (int i = 0; i < CRL_TEST_CHAIN_LEN; i++) {
            EXPECT_NOT_NULL(received_lookup_data.certs[i]);
        }
    };

    /* CRL validation errors when a leaf certificate is revoked */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_crl;
        data.crls[1] = root_crl;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, crl_lookup_test_callback, &data));

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_CRL_LEAF_REVOKED_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data,
                                        chain_len, &pkey_type, &public_key_out),
                S2N_ERR_CERT_REVOKED);
        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    };

    /* CRL validation errors when an intermediate certificate is revoked */
    for (int i = 0; i < 2; i++) {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_revoked_crl;
        data.crls[1] = root_crl;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, crl_lookup_test_callback, &data));

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        if (i == 0) {
            /* Ensure CRL validation fails when only the intermediate certificate is revoked */
            EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_CRL_INTERMEDIATE_REVOKED_CERT_CHAIN, &cert_chain_stuffer));
        } else if (i == 1) {
            /* Ensure CRL validation fails when both the intermediate and leaf certificates are revoked */
            EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_CRL_ALL_REVOKED_CERT_CHAIN, &cert_chain_stuffer));
        }
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data,
                                        chain_len, &pkey_type, &public_key_out),
                S2N_ERR_CERT_REVOKED);
        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    }

    /* CRL validation fails when a certificate is rejected from the callback */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        struct crl_lookup_data data = { 0 };

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, crl_lookup_test_callback, &data));

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_CRL_NONE_REVOKED_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data,
                                        chain_len, &pkey_type, &public_key_out),
                S2N_ERR_CRL_LOOKUP_FAILED);
        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    };

    /* CRL validation succeeds for unrevoked certificate chain when extraneous certificate is rejected */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_crl;
        data.crls[1] = root_crl;

        /* Reject the extraneous cert */
        data.crls[2] = NULL;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, crl_lookup_test_callback, &data));

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE * 2];
        uint32_t pem_len_1 = 0;
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_CRL_NONE_REVOKED_CERT_CHAIN, cert_chain_pem, &pem_len_1,
                S2N_MAX_TEST_PEM_SIZE));

        /* Add an arbitrary cert to the chain that won't be included in the chain of trust */
        uint32_t pem_len_2 = 0;
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_RSA_2048_SHA256_CLIENT_CERT, cert_chain_pem + pem_len_1,
                &pem_len_2, S2N_MAX_TEST_PEM_SIZE));

        uint32_t cert_chain_len = pem_len_1 + pem_len_2;

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem_data(connection, cert_chain_pem, cert_chain_len, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type,
                &public_key_out));
        EXPECT_TRUE(data.callback_invoked_count == 3);
    };

    /* s2n_x509_validator_validate_cert_chain blocks until all CRL callbacks respond */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, crl_lookup_noop, NULL));

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_CRL_NONE_REVOKED_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        /* Blocks if no response received from callbacks */
        for (int i = 0; i < 10; i++) {
            EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                            &pkey_type, &public_key_out),
                    S2N_ERR_ASYNC_BLOCKED);
        }

        /* Continues to block if only one callback has sent a response */
        struct s2n_crl_lookup *lookup = NULL;
        EXPECT_OK(s2n_array_get(validator.crl_lookup_list, 0, (void **) &lookup));
        EXPECT_NOT_NULL(lookup);
        EXPECT_SUCCESS(s2n_crl_lookup_set(lookup, root_crl));
        for (int i = 0; i < 10; ++i) {
            EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                            &pkey_type, &public_key_out),
                    S2N_ERR_ASYNC_BLOCKED);
        }

        /* Unblocks when all callbacks send a response */
        lookup = NULL;
        EXPECT_OK(s2n_array_get(validator.crl_lookup_list, 1, (void **) &lookup));
        EXPECT_NOT_NULL(lookup);
        EXPECT_SUCCESS(s2n_crl_lookup_set(lookup, intermediate_crl));
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type,
                &public_key_out));
    };

    /* CRL validation fails when a callback returns unsuccessfully */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, crl_lookup_callback_fail, NULL));

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_CRL_NONE_REVOKED_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data,
                                        chain_len, &pkey_type, &public_key_out),
                S2N_ERR_CANCELLED);
    };

    /* CRL validation succeeds for a CRL with an invalid thisUpdate date */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_invalid_this_update_crl;
        data.crls[1] = root_crl;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, crl_lookup_test_callback, &data));

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_CRL_NONE_REVOKED_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type,
                &public_key_out));
        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    };

    /* CRL validation fails for a revoked leaf certificate, with a CRL that has an invalid thisUpdate date */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_invalid_this_update_crl;
        data.crls[1] = root_crl;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, crl_lookup_test_callback, &data));

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_CRL_LEAF_REVOKED_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                        &pkey_type, &public_key_out),
                S2N_ERR_CERT_REVOKED);
        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    };

    /* CRL validation succeeds for a CRL with an invalid nextUpdate date */
    for (int disable_time_validation = 0; disable_time_validation <= 1; disable_time_validation += 1) {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_invalid_next_update_crl;
        data.crls[1] = root_crl;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, crl_lookup_test_callback, &data));

        /* Ensure that validation succeeds for a CRL with an invalid nextUpdate field when time
         * validation is disabled.
         */
        if (disable_time_validation) {
            EXPECT_SUCCESS(s2n_config_disable_x509_time_verification(config));
        }

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_CRL_NONE_REVOKED_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type,
                &public_key_out));
        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    };

    /* CRL validation fails for a revoked leaf certificate, with a CRL that has an invalid nextUpdate date */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_invalid_next_update_crl;
        data.crls[1] = root_crl;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, crl_lookup_test_callback, &data));

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(connection, S2N_CRL_LEAF_REVOKED_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                                        &pkey_type, &public_key_out),
                S2N_ERR_CERT_REVOKED);
        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    };

    /* Self-talk: server certificate is not revoked */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_CRL_NONE_REVOKED_CERT_CHAIN, S2N_CRL_NONE_REVOKED_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_CRL_ROOT_CERT, NULL));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_crl;
        data.crls[1] = root_crl;
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, crl_lookup_test_callback, &data));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    };

    /* Self-talk: server certificate is revoked */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_CRL_LEAF_REVOKED_CERT_CHAIN, S2N_CRL_LEAF_REVOKED_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_CRL_ROOT_CERT, NULL));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_crl;
        data.crls[1] = root_crl;
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(config, crl_lookup_test_callback, &data));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                S2N_ERR_CERT_REVOKED);

        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    };

    /* Self-talk: client certificate is not revoked */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *server_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&server_chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, server_chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, S2N_CRL_ROOT_CERT, NULL));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default"));
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_REQUIRED));

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *client_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&client_chain_and_key,
                S2N_CRL_NONE_REVOKED_CERT_CHAIN, S2N_CRL_NONE_REVOKED_KEY));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, client_chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default"));
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_REQUIRED));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_crl;
        data.crls[1] = root_crl;
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(server_config, crl_lookup_test_callback, &data));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(server_conn, verify_host_always_allow, NULL));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "S2nTestServer"));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    };

    /* Self-talk: client certificate is revoked */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *server_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&server_chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, server_chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, S2N_CRL_ROOT_CERT, NULL));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default"));
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_REQUIRED));

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *client_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&client_chain_and_key,
                S2N_CRL_LEAF_REVOKED_CERT_CHAIN, S2N_CRL_LEAF_REVOKED_KEY));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, client_chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default"));
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_REQUIRED));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_crl;
        data.crls[1] = root_crl;
        EXPECT_SUCCESS(s2n_config_set_crl_lookup_cb(server_config, crl_lookup_test_callback, &data));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(server_conn, verify_host_always_allow, NULL));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "S2nTestServer"));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                S2N_ERR_CERT_REVOKED);

        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    };

    /* Calling s2n_crl_lookup return functions correctly set context fields */
    {
        struct s2n_crl_lookup lookup = { 0 };

        lookup.status = AWAITING_RESPONSE;
        EXPECT_SUCCESS(s2n_crl_lookup_set(&lookup, root_crl));
        EXPECT_TRUE(lookup.status == FINISHED);
        EXPECT_NOT_NULL(lookup.crl);

        lookup.status = AWAITING_RESPONSE;
        EXPECT_SUCCESS(s2n_crl_lookup_ignore(&lookup));
        EXPECT_TRUE(lookup.status == FINISHED);
        EXPECT_NULL(lookup.crl);
    };

    /* Certificate issuer hash is retrieved successfully */
    {
        struct s2n_crl_lookup lookup = { 0 };
        EXPECT_NOT_NULL(received_lookup_data.certs[0]);
        lookup.cert = received_lookup_data.certs[0];

        uint64_t hash = 0;
        EXPECT_SUCCESS(s2n_crl_lookup_get_cert_issuer_hash(&lookup, &hash));
        EXPECT_TRUE(hash != 0);
    };

    /* Retrieved hash values for certificates match CRL hashes */
    {
        /* The hash of the leaf certificate matches the hash of the intermediate CRL */

        struct s2n_crl_lookup leaf_lookup = { 0 };
        EXPECT_NOT_NULL(received_lookup_data.certs[0]);
        leaf_lookup.cert = received_lookup_data.certs[0];

        uint64_t leaf_cert_hash = 0;
        EXPECT_SUCCESS(s2n_crl_lookup_get_cert_issuer_hash(&leaf_lookup, &leaf_cert_hash));
        EXPECT_TRUE(leaf_cert_hash != 0);

        uint64_t intermediate_crl_hash = 0;
        EXPECT_SUCCESS(s2n_crl_get_issuer_hash(intermediate_crl, &intermediate_crl_hash));
        EXPECT_TRUE(intermediate_crl_hash != 0);

        EXPECT_TRUE(leaf_cert_hash == intermediate_crl_hash);

        /* The hash of the intermediate certificate matches the hash of the root CRL */

        struct s2n_crl_lookup intermediate_lookup = { 0 };
        EXPECT_NOT_NULL(received_lookup_data.certs[1]);
        intermediate_lookup.cert = received_lookup_data.certs[1];

        uint64_t intermediate_cert_hash = 0;
        EXPECT_SUCCESS(s2n_crl_lookup_get_cert_issuer_hash(&intermediate_lookup, &intermediate_cert_hash));
        EXPECT_TRUE(intermediate_cert_hash != 0);

        uint64_t root_crl_hash = 0;
        EXPECT_SUCCESS(s2n_crl_get_issuer_hash(root_crl, &root_crl_hash));
        EXPECT_TRUE(root_crl_hash != 0);

        EXPECT_TRUE(intermediate_cert_hash == root_crl_hash);

        /* If the certificate and CRL were issued by different CAs, their hashes should not match */
        EXPECT_TRUE(leaf_cert_hash != root_crl_hash);
    };

    /* s2n_crl_validate_active tests */
    {
        /* Succeeds for valid CRL */
        EXPECT_SUCCESS(s2n_crl_validate_active(intermediate_crl));

        /* Succeeds for expired CRL */
        EXPECT_SUCCESS(s2n_crl_validate_active(intermediate_invalid_next_update_crl));

        /* Fails for CRL that is not yet valid */
        EXPECT_FAILURE_WITH_ERRNO(s2n_crl_validate_active(intermediate_invalid_this_update_crl),
                S2N_ERR_CRL_NOT_YET_VALID);
    };

    /* s2n_crl_validate_not_expired tests */
    {
        /* Succeeds for valid CRL */
        EXPECT_SUCCESS(s2n_crl_validate_not_expired(intermediate_crl));

        /* Succeeds for CRL that is not yet valid */
        EXPECT_SUCCESS(s2n_crl_validate_not_expired(intermediate_invalid_this_update_crl));

        /* Fails for expired CRL */
        EXPECT_FAILURE_WITH_ERRNO(s2n_crl_validate_not_expired(intermediate_invalid_next_update_crl),
                S2N_ERR_CRL_EXPIRED);
    };

    END_TEST();
}
