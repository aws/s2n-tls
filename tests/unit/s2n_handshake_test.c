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

#include "testlib/s2n_testlib.h"

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#include <s2n.h>
#include <crypto/s2n_pkey.h>

#include "crypto/s2n_fips.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "utils/s2n_safety.h"

static int try_handshake(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    s2n_blocked_status server_blocked;
    s2n_blocked_status client_blocked;

    int tries = 0;
    do {
        int client_rc = s2n_negotiate(client_conn, &client_blocked);
        if (!(client_rc == 0 || (client_blocked && errno == EAGAIN))) {
            return -1;
        }

        int server_rc = s2n_negotiate(server_conn, &server_blocked);
        if (!(server_rc == 0 || (server_blocked && errno == EAGAIN) || server_blocked == S2N_BLOCKED_ON_APPLICATION_DATA)) {
            return -1;
        }

        tries += 1;
        if (tries == 10) {
            return -1;
        }
    } while (client_blocked || server_blocked);

    uint8_t server_shutdown = 0;
    uint8_t client_shutdown = 0;
    do {
        if (!server_shutdown) {
            int server_rc = s2n_shutdown(server_conn, &server_blocked);
            if (server_rc == 0) {
                server_shutdown = 1;
            } else if (!(server_blocked && errno == EAGAIN)) {
                return -1;
            }
        }

        if (!client_shutdown) {
            int client_rc = s2n_shutdown(client_conn, &client_blocked);
            if (client_rc == 0) {
                client_shutdown = 1;
            } else if (!(client_blocked && errno == EAGAIN)) {
                return -1;
            }
        }
    } while (!server_shutdown || !client_shutdown);

    return 0;
}

int test_cipher_preferences(struct s2n_config *server_config, struct s2n_config *client_config) {
    const struct s2n_cipher_preferences *cipher_preferences;

    cipher_preferences = server_config->cipher_preferences;
    notnull_check(cipher_preferences);

    if (s2n_is_in_fips_mode()) {
        /* Override default client config ciphers when in FIPS mode to ensure all FIPS
         * default ciphers are tested.
         */
        client_config->cipher_preferences = cipher_preferences;
        notnull_check(client_config->cipher_preferences);
    }

    /* Verify that a handshake succeeds for every available cipher in the default list. For unavailable ciphers,
     * make sure that we fail the handshake. */
    for (int cipher_idx = 0; cipher_idx < cipher_preferences->count; cipher_idx++) {
        struct s2n_cipher_preferences server_cipher_preferences;
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        server_conn = s2n_connection_new(S2N_SERVER);
        notnull_check(server_conn);
        int server_to_client[2];
        int client_to_server[2];
        struct s2n_cipher_suite *expected_cipher = cipher_preferences->suites[cipher_idx];
        uint8_t expect_failure = 0;

        /* Expect failure if the libcrypto we're building with can't support the cipher */
        if (!expected_cipher->available) {
            expect_failure = 1;
        }

        /* Craft a cipher preference with a cipher_idx cipher
           NOTE: Its safe to use memcpy as the address of server_cipher_preferences
           will never be NULL */
        memcpy(&server_cipher_preferences, cipher_preferences, sizeof(server_cipher_preferences));
        server_cipher_preferences.count = 1;
        server_cipher_preferences.suites = &expected_cipher;
        server_conn->cipher_pref_override = &server_cipher_preferences;

        /* Create nonblocking pipes */
        GUARD(pipe(server_to_client));
        GUARD(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           ne_check(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           ne_check(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        client_conn = s2n_connection_new(S2N_CLIENT);
        notnull_check(client_conn);
        GUARD(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        GUARD(s2n_connection_set_write_fd(client_conn, client_to_server[1]));
        GUARD(s2n_connection_set_config(client_conn, client_config));
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        client_conn->actual_protocol_version = S2N_TLS12;

        GUARD(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        GUARD(s2n_connection_set_write_fd(server_conn, server_to_client[1]));
        GUARD(s2n_connection_set_config(server_conn, server_config));
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        server_conn->actual_protocol_version = S2N_TLS12;

        if (!expect_failure) {
            GUARD(try_handshake(server_conn, client_conn));
            const char* actual_cipher = s2n_connection_get_cipher(server_conn);
            if (strcmp(actual_cipher, expected_cipher->name) != 0){
                return -1;
            }
        } else {
            eq_check(try_handshake(server_conn, client_conn), -1);
        }

        GUARD(s2n_connection_free(server_conn));
        GUARD(s2n_connection_free(client_conn));

        for (int i = 0; i < 2; i++) {
           GUARD(close(server_to_client[i]));
           GUARD(close(client_to_server[i]));
        }
    }

    return 0;
}

int get_private_key_pem(struct s2n_pkey* pkey, const char *pem_path) {
    char *private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE);
    notnull_check(private_key_pem);
    GUARD(s2n_read_test_pem(pem_path, private_key_pem, S2N_MAX_TEST_PEM_SIZE));

    /* Put the private key pem in a stuffer */
    DEFER_CLEANUP(struct s2n_stuffer key_in_stuffer = {{0}}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer key_out_stuffer = {{0}}, s2n_stuffer_free);
    GUARD(s2n_stuffer_alloc_ro_from_string(&key_in_stuffer, private_key_pem));
    GUARD(s2n_stuffer_growable_alloc(&key_out_stuffer, strlen(private_key_pem)));

    /* Convert pem to asn1 and asn1 to the private key. Handles both PKCS#1 and PKCS#8 formats */
    struct s2n_blob key_blob = {0};
    GUARD(s2n_stuffer_private_key_from_pem(&key_in_stuffer, &key_out_stuffer));
    key_blob.size = s2n_stuffer_data_available(&key_out_stuffer);
    key_blob.data = s2n_stuffer_raw_read(&key_out_stuffer, key_blob.size);
    notnull_check(key_blob.data);

    /* Get key type and create appropriate key context */
    GUARD(s2n_pkey_zero_init(pkey));
    GUARD(s2n_asn1der_to_private_key(pkey, &key_blob));

    free(private_key_pem);
    return 0;
}

int external_rsa_decrypt(uint8_t *ctx, const uint8_t *encrypted_data, uint32_t encrypted_data_length, const char *pem_path) {
    /* Get key type and create appropriate key context */
    DEFER_CLEANUP(struct s2n_pkey pkey = {{{0}}}, s2n_pkey_free);
    GUARD(get_private_key_pem(&pkey, pem_path));

    /* decrypt */
    struct s2n_blob in = {0};
    in.data = (uint8_t*)encrypted_data;
    in.size = encrypted_data_length;

    struct s2n_blob out = {0};
    out.size = S2N_TLS_SECRET_LEN;
    out.data = &ctx[5];

    if (0 != s2n_pkey_decrypt(&pkey, &in, &out))
        return -1;

    ctx[0] = 2;

    return 0;
}

int external_rsa_default_decrypt(uint8_t *ctx, const uint8_t *encrypted_data, uint32_t encrypted_data_length)
{
    return external_rsa_decrypt(ctx, encrypted_data, encrypted_data_length, S2N_DEFAULT_TEST_PRIVATE_KEY);
}

int external_rsa_ecdsa_decrypt(uint8_t *ctx, const uint8_t *encrypted_data, uint32_t encrypted_data_length)
{
    return external_rsa_decrypt(ctx, encrypted_data, encrypted_data_length, S2N_ECDSA_P384_PKCS1_KEY);
}

int external_dhe_sign(uint8_t *status, uint8_t **result, uint8_t hash_algorithm, const uint8_t* hash_digest, const char *pem_path)
{
    // status should not be null and should has value of 1 meaning external request made and currently waiting for result.
    notnull_check(status);
    eq_check(1, *status);

    // result should be null because it's need to be populated by this function
    eq_check(NULL, *result);

    // hash algorithm should be an enum between S2N_HASH_NONE(0) and S2N_HASH_SENTINEL
    gte_check(hash_algorithm, (uint8_t)S2N_HASH_NONE);
    lte_check(hash_algorithm, (uint8_t)S2N_HASH_SENTINEL);

    // hash_digest should not be empty (it should be a array of size S2N_MAX_DIGEST_LEN)
    notnull_check(hash_digest);

    // get the hash digest length
    uint8_t digest_length;
    GUARD(s2n_hash_digest_size((s2n_hash_algorithm)hash_algorithm, &digest_length));
    lte_check(digest_length, S2N_MAX_DIGEST_LEN);

    // create key
    DEFER_CLEANUP(struct s2n_pkey pkey = {{{0}}}, s2n_pkey_free);
    GUARD(get_private_key_pem(&pkey, pem_path));

    // get the certificate type
    int32_t cert_type = -1;
    if (NULL != pkey.encrypt) {
        cert_type = 0;  //RSA
    } else if (NULL != pkey.key.ecdsa_key.ec_key) {
        cert_type = 1;  //EC
    }

    // Prepare the signature blob
    struct s2n_blob signature = {0};
    uint32_t maximum_signature_length = s2n_pkey_size(&pkey);
    GUARD(s2n_alloc(&signature, maximum_signature_length));
    uint32_t signature_size = signature.size;

    int nid_type;
    switch (cert_type)
    {
        case 0:
            //RSA
            GUARD(s2n_hash_NID_type((s2n_hash_algorithm)hash_algorithm, &nid_type));
            GUARD_OSSL(RSA_sign(nid_type, hash_digest, digest_length, signature.data, &signature_size, pkey.key.rsa_key.rsa), S2N_ERR_SIGN);
            break;
        case 1:
            //ECDSA
            GUARD_OSSL(ECDSA_sign(0, hash_digest, digest_length, signature.data, &signature_size, pkey.key.ecdsa_key.ec_key), S2N_ERR_SIGN);
            break;
        default:
            S2N_ERROR(S2N_ERR_EXTERNAL_CERT_TYPE_INVALID);
            break;
    }

    S2N_ERROR_IF(signature_size > signature.size, S2N_ERR_SIZE_MISMATCH);
    signature.size = signature_size;

    // copy signature to the result
    *result = malloc(signature.size + 4);

    if (_IS_BIG_ENDIAN) {
        (*result)[0] = ((uint8_t*)&signature_size)[0];
        (*result)[1] = ((uint8_t*)&signature_size)[1];
        (*result)[2] = ((uint8_t*)&signature_size)[2];
        (*result)[3] = ((uint8_t*)&signature_size)[3];
    } else {
        (*result)[0] = ((uint8_t*)&signature_size)[3];
        (*result)[1] = ((uint8_t*)&signature_size)[2];
        (*result)[2] = ((uint8_t*)&signature_size)[1];
        (*result)[3] = ((uint8_t*)&signature_size)[0];
    }

    memcpy_check((*result + 4), signature.data, signature_size);
    *status = 2;

    // free local memory
    s2n_free(&signature);

    return 0;
}

int external_dhe_default_sign(uint8_t *status, uint8_t **result, uint8_t hash_algorithm, const uint8_t* hash_digest)
{
    return external_dhe_sign(status, result, hash_algorithm, hash_digest, S2N_DEFAULT_TEST_PRIVATE_KEY);
}

int external_dhe_ecdsa_sign(uint8_t *status, uint8_t **result, uint8_t hash_algorithm, const uint8_t* hash_digest)
{
    return external_dhe_sign(status, result, hash_algorithm, hash_digest, S2N_ECDSA_P384_PKCS1_KEY);
}

int main(int argc, char **argv)
{

    BEGIN_TEST();

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    // test_with_rsa_cert();
    {
        struct s2n_config *server_config, *client_config;
        char *cert_chain_pem;
        char *private_key_pem;
        char *dhparams_pem;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_NOT_NULL(server_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));

        client_config = s2n_fetch_unsafe_client_testing_config();

        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        free(cert_chain_pem);
        free(private_key_pem);
        free(dhparams_pem);

    }

    // test with external rsa decrypt, note that private_key_pem is not needed for setting up the config
    {
        struct s2n_config *server_config, *client_config;
        char *cert_chain_pem;
        char *dhparams_pem;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_NOT_NULL(server_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_with_external_decrypt(server_config, cert_chain_pem, external_rsa_default_decrypt, external_dhe_default_sign));

        client_config = s2n_fetch_unsafe_client_testing_config();

        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        free(cert_chain_pem);
        free(dhparams_pem);
    }

    //    test_with_ecdsa_cert()
    {
        struct s2n_config *server_config, *client_config;
        char *cert_chain_pem;
        char *private_key_pem;
        char *dhparams_pem;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_NOT_NULL(server_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all_ecdsa"));

        EXPECT_NOT_NULL(client_config = s2n_fetch_unsafe_client_ecdsa_testing_config());

        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_ECDSA_P384_PKCS1_CERT_CHAIN, NULL));
        
        EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        free(cert_chain_pem);
        free(private_key_pem);
        free(dhparams_pem);

    }

    //    test with external ecdsa cert decrypt and signing
    {
        struct s2n_config *server_config, *client_config;
        char *cert_chain_pem;
        char *dhparams_pem;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_NOT_NULL(server_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_with_external_decrypt(server_config, cert_chain_pem, external_rsa_ecdsa_decrypt, external_dhe_ecdsa_sign));
        EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all_ecdsa"));

        EXPECT_NOT_NULL(client_config = s2n_fetch_unsafe_client_ecdsa_testing_config());

        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_ECDSA_P384_PKCS1_CERT_CHAIN, NULL));

        EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        free(cert_chain_pem);
        free(dhparams_pem);
    }

    END_TEST();
    return 0;
}

