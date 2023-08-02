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

#include "crypto/s2n_ecdsa.h"
#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_certificate_verify.c"

uint8_t hello[] = "Hello, World!\n";
uint8_t goodbye[] = "Goodbye, World!\n";

struct s2n_tls13_cert_verify_test {
    const char *const cert_file;
    const char *const key_file;
    const struct s2n_signature_scheme *sig_scheme;
    const s2n_mode sender_mode;
    const s2n_mode verifier_mode;
};

const struct s2n_tls13_cert_verify_test test_cases[] = {
    { .cert_file = S2N_ECDSA_P384_PKCS1_CERT_CHAIN, .key_file = S2N_ECDSA_P384_PKCS1_KEY, .sig_scheme = &s2n_ecdsa_secp256r1_sha256 },
#if RSA_PSS_CERTS_SUPPORTED
    { .cert_file = S2N_RSA_PSS_2048_SHA256_LEAF_CERT, .key_file = S2N_RSA_PSS_2048_SHA256_LEAF_KEY, .sig_scheme = &s2n_rsa_pss_pss_sha256 },
#endif
};

int run_tests(const struct s2n_tls13_cert_verify_test *test_case, s2n_mode verifier_mode)
{
    const char *cert_file = test_case->cert_file;
    const char *key_file = test_case->key_file;
    struct s2n_signature_scheme sig_scheme = *test_case->sig_scheme;

    struct s2n_config *config = NULL;
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20200207"));

    /* Successfully send and receive certificate verify */
    {
        /* Derive private/public keys and set connection variables */
        struct s2n_stuffer certificate_in = { 0 }, certificate_out = { 0 };
        struct s2n_blob b = { 0 };
        struct s2n_cert_chain_and_key *cert_chain = NULL;
        char *cert_chain_pem = NULL;
        char *private_key_pem = NULL;
        s2n_pkey_type pkey_type = { 0 };

        struct s2n_connection *verifying_conn = NULL, *sending_conn = NULL;
        EXPECT_NOT_NULL(verifying_conn = s2n_connection_new(verifier_mode));
        verifying_conn->actual_protocol_version = S2N_TLS13;
        EXPECT_NOT_NULL(sending_conn = s2n_connection_new(verifier_mode == S2N_CLIENT ? S2N_SERVER : S2N_CLIENT));

        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(cert_chain = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(cert_file, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(key_file, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(cert_chain, cert_chain_pem, private_key_pem));

        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert_chain));
        EXPECT_SUCCESS(s2n_connection_set_config(sending_conn, config));
        sending_conn->handshake_params.our_chain_and_key = cert_chain;
        sending_conn->handshake_params.server_cert_sig_scheme = &sig_scheme;
        sending_conn->handshake_params.client_cert_sig_scheme = &sig_scheme;
        sending_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
        sending_conn->actual_protocol_version = S2N_TLS13;

        EXPECT_SUCCESS(s2n_connection_set_config(verifying_conn, config));
        verifying_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

        EXPECT_SUCCESS(s2n_blob_init(&b, (uint8_t *) cert_chain_pem, strlen(cert_chain_pem) + 1));
        EXPECT_SUCCESS(s2n_stuffer_write(&certificate_in, &b));
        EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));

        /* Extract public key from certificate and set it for verifying connection */
        uint32_t available_size = s2n_stuffer_data_available(&certificate_out);
        EXPECT_SUCCESS(s2n_blob_init(&b, s2n_stuffer_raw_read(&certificate_out, available_size), available_size));
        if (verifying_conn->mode == S2N_CLIENT) {
            EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&verifying_conn->handshake_params.server_public_key, &pkey_type, &b));
            EXPECT_SUCCESS(s2n_pkey_match(&verifying_conn->handshake_params.server_public_key, sending_conn->handshake_params.our_chain_and_key->private_key));
        } else {
            EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&verifying_conn->handshake_params.client_public_key, &pkey_type, &b));
            EXPECT_SUCCESS(s2n_pkey_match(&verifying_conn->handshake_params.client_public_key, sending_conn->handshake_params.our_chain_and_key->private_key));
        }

        /* Hash initialization */
        EXPECT_SUCCESS(s2n_hash_init(&sending_conn->handshake.hashes->sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&sending_conn->handshake.hashes->sha256, hello, strlen((char *) hello)));
        EXPECT_SUCCESS(s2n_hash_init(&verifying_conn->handshake.hashes->sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&verifying_conn->handshake.hashes->sha256, hello, strlen((char *) hello)));

        /* Send cert verify */
        EXPECT_SUCCESS(s2n_tls13_cert_verify_send(sending_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&sending_conn->handshake.io, &verifying_conn->handshake.io, s2n_stuffer_data_available(&sending_conn->handshake.io)));

        /* Receive and verify cert */
        EXPECT_SUCCESS(s2n_tls13_cert_verify_recv(verifying_conn));

        /* Repeat the above test successfully */
        EXPECT_SUCCESS(s2n_tls13_cert_verify_send(sending_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&sending_conn->handshake.io, &verifying_conn->handshake.io, s2n_stuffer_data_available(&sending_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_tls13_cert_verify_recv(verifying_conn));

        /* Test fails if cipher suites hash is configured incorrectly */
        verifying_conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
        EXPECT_SUCCESS(s2n_tls13_cert_verify_send(sending_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&sending_conn->handshake.io, &verifying_conn->handshake.io, s2n_stuffer_data_available(&sending_conn->handshake.io)));
        EXPECT_FAILURE(s2n_tls13_cert_verify_recv(verifying_conn));

        /* Clean up */
        free(cert_chain_pem);
        free(private_key_pem);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(cert_chain));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_in));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_out));
        EXPECT_SUCCESS(s2n_connection_free(sending_conn));
        EXPECT_SUCCESS(s2n_connection_free(verifying_conn));
    };

    /* Verifying connection errors with incorrect signed content */
    {
        /* Derive private/public keys and set connection variables */
        struct s2n_stuffer certificate_in = { 0 }, certificate_out = { 0 };
        struct s2n_blob b = { 0 };
        struct s2n_cert_chain_and_key *cert_chain = NULL;
        char *cert_chain_pem = NULL;
        char *private_key_pem = NULL;
        uint64_t bytes_in_hash = 0;
        s2n_pkey_type pkey_type = { 0 };

        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(cert_chain = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(cert_file, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(key_file, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(cert_chain, cert_chain_pem, private_key_pem));

        struct s2n_connection *verifying_conn = NULL;
        EXPECT_NOT_NULL(verifying_conn = s2n_connection_new(verifier_mode));
        verifying_conn->actual_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert_chain));
        EXPECT_SUCCESS(s2n_connection_set_config(verifying_conn, config));
        verifying_conn->handshake_params.our_chain_and_key = cert_chain;
        verifying_conn->handshake_params.server_cert_sig_scheme = &sig_scheme;
        verifying_conn->handshake_params.client_cert_sig_scheme = &sig_scheme;
        verifying_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

        EXPECT_SUCCESS(s2n_blob_init(&b, (uint8_t *) cert_chain_pem, strlen(cert_chain_pem) + 1));
        EXPECT_SUCCESS(s2n_stuffer_write(&certificate_in, &b));
        EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));

        uint32_t available_size = s2n_stuffer_data_available(&certificate_out);
        EXPECT_SUCCESS(s2n_blob_init(&b, s2n_stuffer_raw_read(&certificate_out, available_size), available_size));
        if (verifying_conn->mode == S2N_CLIENT) {
            EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&verifying_conn->handshake_params.server_public_key, &pkey_type, &b));
            EXPECT_SUCCESS(s2n_pkey_match(&verifying_conn->handshake_params.server_public_key, verifying_conn->handshake_params.our_chain_and_key->private_key));
        } else {
            EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&verifying_conn->handshake_params.client_public_key, &pkey_type, &b));
            EXPECT_SUCCESS(s2n_pkey_match(&verifying_conn->handshake_params.client_public_key, verifying_conn->handshake_params.our_chain_and_key->private_key));
        }
        /* Initialize send hash with hello */
        EXPECT_SUCCESS(s2n_hash_init(&verifying_conn->handshake.hashes->sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&verifying_conn->handshake.hashes->sha256, hello, strlen((char *) hello)));
        EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&verifying_conn->handshake.hashes->sha256, &bytes_in_hash));
        EXPECT_EQUAL(bytes_in_hash, 14);

        /* Send and receive cert verify */
        EXPECT_SUCCESS(s2n_tls13_cert_verify_send(verifying_conn));

        /* Initialize receive hash with goodbye */
        EXPECT_SUCCESS(s2n_hash_init(&verifying_conn->handshake.hashes->sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&verifying_conn->handshake.hashes->sha256, goodbye, strlen((char *) goodbye)));
        EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&verifying_conn->handshake.hashes->sha256, &bytes_in_hash));
        EXPECT_EQUAL(bytes_in_hash, 16);

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_verify_recv(verifying_conn), S2N_ERR_VERIFY_SIGNATURE);

        EXPECT_SUCCESS(s2n_pkey_free(&verifying_conn->handshake_params.client_public_key));

        /* Clean up */
        free(cert_chain_pem);
        free(private_key_pem);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(cert_chain));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_in));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_out));
        EXPECT_SUCCESS(s2n_connection_free(verifying_conn));
    };

    /* Verifying connection errors with even 1 bit incorrect */
    {
        struct s2n_stuffer certificate_in = { 0 }, certificate_out = { 0 };
        struct s2n_blob b = { 0 };
        struct s2n_cert_chain_and_key *cert_chain = NULL;
        char *cert_chain_pem = NULL;
        char *private_key_pem = NULL;
        s2n_pkey_type pkey_type = { 0 };

        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(cert_chain = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(cert_file, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(key_file, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(cert_chain, cert_chain_pem, private_key_pem));

        struct s2n_connection *verifying_conn = NULL;
        EXPECT_NOT_NULL(verifying_conn = s2n_connection_new(verifier_mode));
        verifying_conn->actual_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert_chain));
        EXPECT_SUCCESS(s2n_connection_set_config(verifying_conn, config));
        verifying_conn->handshake_params.our_chain_and_key = cert_chain;
        verifying_conn->handshake_params.server_cert_sig_scheme = &sig_scheme;
        verifying_conn->handshake_params.client_cert_sig_scheme = &sig_scheme;
        verifying_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

        EXPECT_SUCCESS(s2n_blob_init(&b, (uint8_t *) cert_chain_pem, strlen(cert_chain_pem) + 1));
        EXPECT_SUCCESS(s2n_stuffer_write(&certificate_in, &b));
        EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));

        uint32_t available_size = s2n_stuffer_data_available(&certificate_out);
        EXPECT_SUCCESS(s2n_blob_init(&b, s2n_stuffer_raw_read(&certificate_out, available_size), available_size));
        if (verifying_conn->mode == S2N_CLIENT) {
            EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&verifying_conn->handshake_params.server_public_key, &pkey_type, &b));
        } else {
            EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&verifying_conn->handshake_params.client_public_key, &pkey_type, &b));
        }

        /* Initialize send hash with hello */
        EXPECT_SUCCESS(s2n_hash_init(&verifying_conn->handshake.hashes->sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&verifying_conn->handshake.hashes->sha256, hello, strlen((char *) hello)));

        /* Send and receive cert verify */
        EXPECT_SUCCESS(s2n_tls13_cert_verify_send(verifying_conn));

        /* Initialize receive hash with hello and flip one bit in verifying_conn io buffer */
        EXPECT_SUCCESS(s2n_hash_init(&verifying_conn->handshake.hashes->sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&verifying_conn->handshake.hashes->sha256, hello, strlen((char *) hello)));
        EXPECT_TRUE(10 < s2n_stuffer_data_available(&verifying_conn->handshake.io));
        verifying_conn->handshake.io.blob.data[10] ^= 1;

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_verify_recv(verifying_conn), S2N_ERR_VERIFY_SIGNATURE);

        /* Clean up */
        if (verifying_conn->mode == S2N_CLIENT) {
            EXPECT_SUCCESS(s2n_pkey_free(&verifying_conn->handshake_params.server_public_key));
        } else {
            EXPECT_SUCCESS(s2n_pkey_free(&verifying_conn->handshake_params.client_public_key));
        }

        free(cert_chain_pem);
        free(private_key_pem);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(cert_chain));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_in));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_out));
        EXPECT_SUCCESS(s2n_connection_free(verifying_conn));
    };

    /* Verifying connection errors with wrong hash/signature algorithms */
    {
        /* Derive private/public keys and set connection variables */
        struct s2n_stuffer certificate_in = { 0 }, certificate_out = { 0 };
        struct s2n_blob b = { 0 };
        struct s2n_cert_chain_and_key *cert_chain = NULL;
        char *cert_chain_pem = NULL;
        char *private_key_pem = NULL;
        s2n_pkey_type pkey_type = { 0 };

        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(cert_chain = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(cert_file, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(key_file, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(cert_chain, cert_chain_pem, private_key_pem));

        struct s2n_connection *verifying_conn = NULL;
        EXPECT_NOT_NULL(verifying_conn = s2n_connection_new(verifier_mode));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert_chain));
        EXPECT_SUCCESS(s2n_connection_set_config(verifying_conn, config));
        verifying_conn->handshake_params.our_chain_and_key = cert_chain;
        verifying_conn->handshake_params.server_cert_sig_scheme = &sig_scheme;
        verifying_conn->handshake_params.client_cert_sig_scheme = &sig_scheme;
        verifying_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
        verifying_conn->actual_protocol_version = S2N_TLS13;

        EXPECT_SUCCESS(s2n_blob_init(&b, (uint8_t *) cert_chain_pem, strlen(cert_chain_pem) + 1));
        EXPECT_SUCCESS(s2n_stuffer_write(&certificate_in, &b));

        EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));

        uint32_t available_size = s2n_stuffer_data_available(&certificate_out);
        EXPECT_SUCCESS(s2n_blob_init(&b, s2n_stuffer_raw_read(&certificate_out, available_size), available_size));
        if (verifying_conn->mode == S2N_CLIENT) {
            EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&verifying_conn->handshake_params.server_public_key, &pkey_type, &b));
        } else {
            EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&verifying_conn->handshake_params.client_public_key, &pkey_type, &b));
        }

        /* Hash initialization */
        EXPECT_SUCCESS(s2n_hash_init(&verifying_conn->handshake.hashes->sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&verifying_conn->handshake.hashes->sha256, hello, strlen((char *) hello)));

        /* Send and receive with mismatched hash algs */
        EXPECT_SUCCESS(s2n_tls13_cert_verify_send(verifying_conn));

        /* Reinitialize hash */
        EXPECT_SUCCESS(s2n_hash_init(&verifying_conn->handshake.hashes->sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&verifying_conn->handshake.hashes->sha256, hello, strlen((char *) hello)));

        /* In this case it doesn't matter if we use conn_sig_scheme or client_cert_sig_scheme as they are currently equal */
        struct s2n_signature_scheme test_scheme = *verifying_conn->handshake_params.server_cert_sig_scheme;
        verifying_conn->handshake_params.server_cert_sig_scheme = &test_scheme;
        test_scheme.hash_alg = S2N_HASH_SHA1;
        EXPECT_FAILURE(s2n_tls13_cert_read_and_verify_signature(verifying_conn,
                verifying_conn->handshake_params.server_cert_sig_scheme));

        /* send and receive with mismatched signature algs */
        verifying_conn->handshake_params.client_cert_sig_scheme = &test_scheme;
        test_scheme.hash_alg = S2N_HASH_SHA256;
        test_scheme.sig_alg = S2N_SIGNATURE_ECDSA;
        test_scheme.iana_value = 0xFFFF;

        EXPECT_SUCCESS(s2n_hash_init(&verifying_conn->handshake.hashes->sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&verifying_conn->handshake.hashes->sha256, hello, strlen((char *) hello)));

        EXPECT_SUCCESS(s2n_tls13_cert_verify_send(verifying_conn));

        EXPECT_SUCCESS(s2n_hash_init(&verifying_conn->handshake.hashes->sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&verifying_conn->handshake.hashes->sha256, hello, strlen((char *) hello)));

        EXPECT_FAILURE(s2n_tls13_cert_verify_recv(verifying_conn));

        /* Clean up */
        if (verifying_conn->mode == S2N_CLIENT) {
            EXPECT_SUCCESS(s2n_pkey_free(&verifying_conn->handshake_params.server_public_key));
        } else {
            EXPECT_SUCCESS(s2n_pkey_free(&verifying_conn->handshake_params.client_public_key));
        }

        free(cert_chain_pem);
        free(private_key_pem);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(cert_chain));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_in));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_out));
        EXPECT_SUCCESS(s2n_connection_free(verifying_conn));
    };

    EXPECT_SUCCESS(s2n_config_free(config));

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(struct s2n_tls13_cert_verify_test); i++) {
        /* Run all tests for server sending and client receiving/verifying cert_verify message */
        run_tests(&test_cases[i], S2N_CLIENT);

        /* Run all tests for client sending and server receiving/verifying cert_verify message */
        run_tests(&test_cases[i], S2N_SERVER);
    }

    END_TEST();
}
