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
#include "crypto/s2n_fips.h"
#include "crypto/s2n_rsa_pss.h"
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
    const struct s2n_signature_scheme *with_wrong_hash;
};

const struct s2n_tls13_cert_verify_test test_cases[] = {
    {
            .cert_file = S2N_ECDSA_P256_PKCS1_CERT_CHAIN,
            .key_file = S2N_ECDSA_P256_PKCS1_KEY,
            .sig_scheme = &s2n_ecdsa_sha256,
            .with_wrong_hash = &s2n_ecdsa_sha384,
    },
#if RSA_PSS_CERTS_SUPPORTED
    {
            .cert_file = S2N_RSA_PSS_2048_SHA256_LEAF_CERT,
            .key_file = S2N_RSA_PSS_2048_SHA256_LEAF_KEY,
            .sig_scheme = &s2n_rsa_pss_pss_sha256,
            .with_wrong_hash = &s2n_rsa_pss_pss_sha384,
    },
#endif
};

S2N_RESULT s2n_cert_verify_connection_setup_and_send(
        struct s2n_connection *sending_conn, struct s2n_connection *verifying_conn,
        struct s2n_config *config, struct s2n_cert_chain_and_key *cert_chain,
        struct s2n_signature_scheme *sig_scheme, struct s2n_blob *cert)
{
    sending_conn->handshake_params.our_chain_and_key = cert_chain;
    sending_conn->handshake_params.server_cert_sig_scheme = sig_scheme;
    sending_conn->handshake_params.client_cert_sig_scheme = sig_scheme;
    sending_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
    sending_conn->actual_protocol_version = S2N_TLS13;
    EXPECT_SUCCESS(s2n_connection_set_config(sending_conn, config));

    verifying_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
    verifying_conn->actual_protocol_version = S2N_TLS13;
    EXPECT_SUCCESS(s2n_connection_set_config(verifying_conn, config));

    /* Extract public key from certificate and set it for verifying connection */
    s2n_pkey_type pkey_type = { 0 };
    if (verifying_conn->mode == S2N_CLIENT) {
        EXPECT_OK(s2n_asn1der_to_public_key_and_type(&verifying_conn->handshake_params.server_public_key, &pkey_type, cert));
        EXPECT_SUCCESS(s2n_pkey_match(&verifying_conn->handshake_params.server_public_key, sending_conn->handshake_params.our_chain_and_key->private_key));
    } else {
        EXPECT_OK(s2n_asn1der_to_public_key_and_type(&verifying_conn->handshake_params.client_public_key, &pkey_type, cert));
        EXPECT_SUCCESS(s2n_pkey_match(&verifying_conn->handshake_params.client_public_key, sending_conn->handshake_params.our_chain_and_key->private_key));
    }

    /* Hash initialization */
    EXPECT_SUCCESS(s2n_hash_init(&sending_conn->handshake.hashes->sha256, S2N_HASH_SHA256));
    EXPECT_SUCCESS(s2n_hash_update(&sending_conn->handshake.hashes->sha256, hello, sizeof(hello)));
    EXPECT_SUCCESS(s2n_hash_init(&verifying_conn->handshake.hashes->sha256, S2N_HASH_SHA256));
    EXPECT_SUCCESS(s2n_hash_update(&verifying_conn->handshake.hashes->sha256, hello, sizeof(hello)));

    /* Send cert verify */
    EXPECT_SUCCESS(s2n_tls13_cert_verify_send(sending_conn));
    EXPECT_SUCCESS(s2n_stuffer_copy(&sending_conn->handshake.io, &verifying_conn->handshake.io,
            s2n_stuffer_data_available(&sending_conn->handshake.io)));

    return S2N_RESULT_OK;
}

int run_tests(const struct s2n_tls13_cert_verify_test *test_case, s2n_mode verifier_mode)
{
    const char *cert_file = test_case->cert_file;
    const char *key_file = test_case->key_file;
    struct s2n_signature_scheme sig_scheme = *test_case->sig_scheme;

    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    char private_key_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    EXPECT_SUCCESS(s2n_read_test_pem(cert_file, &cert_chain_pem[0], S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(key_file, &private_key_pem[0], S2N_MAX_TEST_PEM_SIZE));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *cert_chain = s2n_cert_chain_and_key_new(),
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_NOT_NULL(cert_chain);
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(cert_chain, cert_chain_pem, private_key_pem));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20200207"));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert_chain));

    /* Initialize a certificate */
    DEFER_CLEANUP(struct s2n_stuffer certificate_in = { 0 }, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer certificate_out = { 0 }, s2n_stuffer_free);
    EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_write_bytes(&certificate_in, (uint8_t *) cert_chain_pem, sizeof(cert_chain_pem)));
    EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));

    uint32_t available_size = s2n_stuffer_data_available(&certificate_out);
    struct s2n_blob cert = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&cert, s2n_stuffer_raw_read(&certificate_out, available_size), available_size));

    /* Successfully send and receive certificate verify */
    {
        DEFER_CLEANUP(struct s2n_connection *sending_conn = s2n_connection_new(S2N_PEER_MODE(verifier_mode)),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(sending_conn);

        DEFER_CLEANUP(struct s2n_connection *verifying_conn = s2n_connection_new(verifier_mode),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(verifying_conn);

        EXPECT_OK(s2n_cert_verify_connection_setup_and_send(sending_conn, verifying_conn, config, cert_chain, &sig_scheme, &cert));

        /* Receive and verify cert */
        EXPECT_SUCCESS(s2n_tls13_cert_verify_recv(verifying_conn));

        /* Repeat the above test successfully */
        EXPECT_SUCCESS(s2n_tls13_cert_verify_send(sending_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&sending_conn->handshake.io, &verifying_conn->handshake.io,
                s2n_stuffer_data_available(&sending_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_tls13_cert_verify_recv(verifying_conn));

        /* Test fails if cipher suites hash is configured incorrectly */
        verifying_conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
        EXPECT_SUCCESS(s2n_tls13_cert_verify_send(sending_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&sending_conn->handshake.io, &verifying_conn->handshake.io,
                s2n_stuffer_data_available(&sending_conn->handshake.io)));

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_verify_recv(verifying_conn), S2N_ERR_VERIFY_SIGNATURE);
    };

    /* Verifying connection errors with incorrect signed content */
    {
        DEFER_CLEANUP(struct s2n_connection *sending_conn = s2n_connection_new(S2N_PEER_MODE(verifier_mode)),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(sending_conn);

        DEFER_CLEANUP(struct s2n_connection *verifying_conn = s2n_connection_new(verifier_mode),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(verifying_conn);

        EXPECT_OK(s2n_cert_verify_connection_setup_and_send(sending_conn, verifying_conn, config, cert_chain, &sig_scheme, &cert));

        /* Update receive hash with goodbye */
        EXPECT_SUCCESS(s2n_hash_update(&verifying_conn->handshake.hashes->sha256, goodbye, sizeof(goodbye)));

        uint64_t verifying_bytes = 0;
        uint64_t sending_bytes = 0;
        EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&verifying_conn->handshake.hashes->sha256, &verifying_bytes));
        EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&sending_conn->handshake.hashes->sha256, &sending_bytes));
        EXPECT_NOT_EQUAL(sending_bytes, verifying_bytes);

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_verify_recv(verifying_conn), S2N_ERR_VERIFY_SIGNATURE);
    };

    /* Verifying connection errors with even 1 bit incorrect */
    {
        DEFER_CLEANUP(struct s2n_connection *sending_conn = s2n_connection_new(S2N_PEER_MODE(verifier_mode)),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(sending_conn);

        DEFER_CLEANUP(struct s2n_connection *verifying_conn = s2n_connection_new(verifier_mode),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(verifying_conn);

        EXPECT_OK(s2n_cert_verify_connection_setup_and_send(sending_conn, verifying_conn, config, cert_chain, &sig_scheme, &cert));

        /* Flip one bit in verifying_conn io buffer */
        EXPECT_TRUE(10 < s2n_stuffer_data_available(&verifying_conn->handshake.io));
        verifying_conn->handshake.io.blob.data[10] ^= 1;

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_verify_recv(verifying_conn), S2N_ERR_VERIFY_SIGNATURE);
    };

    /* Verifying connection errors with wrong hash algorithms */
    {
        DEFER_CLEANUP(struct s2n_connection *sending_conn = s2n_connection_new(S2N_PEER_MODE(verifier_mode)),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(sending_conn);

        DEFER_CLEANUP(struct s2n_connection *verifying_conn = s2n_connection_new(verifier_mode),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(verifying_conn);

        EXPECT_OK(s2n_cert_verify_connection_setup_and_send(sending_conn, verifying_conn, config, cert_chain, &sig_scheme, &cert));

        /* Use a hash algorithm different from sender by prepending corresponding iana value */
        struct s2n_stuffer rereader = verifying_conn->handshake.io;
        EXPECT_SUCCESS(s2n_stuffer_rewrite(&rereader));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&rereader, test_case->with_wrong_hash->iana_value));

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_verify_recv(verifying_conn), S2N_ERR_VERIFY_SIGNATURE);
    };

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
