/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "error/s2n_errno.h"
#include "crypto/s2n_ecdsa.h"

/* included to test s2n_server_cert_read_and_verify_signature() */
#include "tls/s2n_server_cert_verify.c"

uint8_t hello[] = "Hello, World!\n";
uint8_t goodbye[] = "Goodbye, World!\n";

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());

    /* Successfully send and receive certificate verify */
    {
        /* Derive private/public keys and set connection variables */
        struct s2n_stuffer certificate_in, certificate_out;
        struct s2n_blob b;
        struct s2n_cert_chain_and_key *ecdsa_cert;
        char *cert_chain_pem;
        char *private_key_pem;
        s2n_pkey_type pkey_type;

        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(ecdsa_cert = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(ecdsa_cert, cert_chain_pem, private_key_pem));

        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        server_conn->handshake_params.our_chain_and_key = ecdsa_cert;
        server_conn->secure.conn_sig_scheme = s2n_ecdsa_secp256r1_sha256;
        server_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
        client_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

        b.data = (uint8_t *) cert_chain_pem;
        b.size = strlen(cert_chain_pem) + 1;
        EXPECT_SUCCESS(s2n_stuffer_write(&certificate_in, &b));
        EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));

        /* Extract public key from certificate and set it for client */
        b.size = s2n_stuffer_data_available(&certificate_out);
        b.data = s2n_stuffer_raw_read(&certificate_out, b.size);
        EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&client_conn->secure.server_public_key, &pkey_type, &b));
        EXPECT_SUCCESS(s2n_pkey_match(&client_conn->secure.server_public_key, server_conn->handshake_params.our_chain_and_key->private_key));

        /* Hash initialization */
        EXPECT_SUCCESS(s2n_hash_init(&server_conn->handshake.sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&server_conn->handshake.sha256, hello, strlen((char *)hello)));
        EXPECT_SUCCESS(s2n_hash_init(&client_conn->handshake.sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&client_conn->handshake.sha256, hello, strlen((char *)hello)));

        /* Send cert verify */
        EXPECT_SUCCESS(s2n_server_cert_verify_send(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, s2n_stuffer_data_available(&server_conn->handshake.io)));

        /* Receive and verify cert */
        EXPECT_SUCCESS(s2n_server_cert_verify_recv(client_conn));
        EXPECT_EQUAL(client_conn->secure.conn_sig_scheme.iana_value, TLS_SIGNATURE_SCHEME_ECDSA_SHA256);

        /* Repeat the above test succesfully */
        EXPECT_SUCCESS(s2n_server_cert_verify_send(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, s2n_stuffer_data_available(&server_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_server_cert_verify_recv(client_conn));

        /* Test fails if cipher suites hash is configured incorrectly */
        client_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
        EXPECT_SUCCESS(s2n_server_cert_verify_send(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, s2n_stuffer_data_available(&server_conn->handshake.io)));
        EXPECT_FAILURE(s2n_server_cert_verify_recv(client_conn));

        /* Clean up */
        free(cert_chain_pem);
        free(private_key_pem);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_in));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_out));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Client errors with incorrect signed content */
    {
        /* Derive private/public keys and set connection variables */
        struct s2n_stuffer certificate_in, certificate_out;
        struct s2n_blob b;
        struct s2n_cert_chain_and_key *ecdsa_cert;
        char *cert_chain_pem;
        char *private_key_pem;
        uint64_t bytes_in_hash;
        s2n_pkey_type pkey_type;

        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(ecdsa_cert = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(ecdsa_cert, cert_chain_pem, private_key_pem));

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        client_conn->handshake_params.our_chain_and_key = ecdsa_cert;
        client_conn->secure.conn_sig_scheme = s2n_ecdsa_secp256r1_sha256;
        client_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

        b.data = (uint8_t *) cert_chain_pem;
        b.size = strlen(cert_chain_pem) + 1;
        EXPECT_SUCCESS(s2n_stuffer_write(&certificate_in, &b));
        EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));

        b.size = s2n_stuffer_data_available(&certificate_out);
        b.data = s2n_stuffer_raw_read(&certificate_out, b.size);
        EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&client_conn->secure.server_public_key, &pkey_type, &b));

        EXPECT_SUCCESS(s2n_pkey_match(&client_conn->secure.server_public_key, client_conn->handshake_params.our_chain_and_key->private_key));

        /* Initialize send hash with hello */
        EXPECT_SUCCESS(s2n_hash_init(&client_conn->handshake.sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&client_conn->handshake.sha256, hello, strlen((char *)hello)));
        EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&client_conn->handshake.sha256, &bytes_in_hash));
        EXPECT_EQUAL(bytes_in_hash, 14);

        /* Send and receive cert verify */
        EXPECT_SUCCESS(s2n_server_cert_verify_send(client_conn));

        /* Initialize receive hash with goodbye */
        EXPECT_SUCCESS(s2n_hash_init(&client_conn->handshake.sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&client_conn->handshake.sha256, goodbye, strlen((char *)goodbye)));
        EXPECT_SUCCESS(s2n_hash_get_currently_in_hash_total(&client_conn->handshake.sha256, &bytes_in_hash));
        EXPECT_EQUAL(bytes_in_hash, 16);

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_cert_verify_recv(client_conn), S2N_ERR_VERIFY_SIGNATURE);

        /* Clean up */
        free(cert_chain_pem);
        free(private_key_pem);
        EXPECT_SUCCESS(s2n_pkey_free(&client_conn->secure.server_public_key));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_in));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_out));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Client errors with even 1 bit incorrect */
    {
        struct s2n_stuffer certificate_in, certificate_out;
        struct s2n_blob b;
        struct s2n_cert_chain_and_key *ecdsa_cert;
        char *cert_chain_pem;
        char *private_key_pem;
        s2n_pkey_type pkey_type;

        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(ecdsa_cert = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(ecdsa_cert, cert_chain_pem, private_key_pem));

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        client_conn->handshake_params.our_chain_and_key = ecdsa_cert;
        client_conn->secure.conn_sig_scheme = s2n_ecdsa_secp256r1_sha256;
        client_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

        b.data = (uint8_t *) cert_chain_pem;
        b.size = strlen(cert_chain_pem) + 1;
        EXPECT_SUCCESS(s2n_stuffer_write(&certificate_in, &b));
        EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));

        b.size = s2n_stuffer_data_available(&certificate_out);
        b.data = s2n_stuffer_raw_read(&certificate_out, b.size);
        EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&client_conn->secure.server_public_key, &pkey_type, &b));

        /* Initialize send hash with hello */
        EXPECT_SUCCESS(s2n_hash_init(&client_conn->handshake.sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&client_conn->handshake.sha256, hello, strlen((char *)hello)));

        /* Send and receive cert verify */
        EXPECT_SUCCESS(s2n_server_cert_verify_send(client_conn));

        /* Initialize receive hash with hello and flip one bit in client_conn io buffer */
        EXPECT_SUCCESS(s2n_hash_init(&client_conn->handshake.sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&client_conn->handshake.sha256, hello, strlen((char *)hello)));
        EXPECT_TRUE(10 < s2n_stuffer_data_available(&client_conn->handshake.io));
        client_conn->handshake.io.blob.data[10] ^= 1;

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_cert_verify_recv(client_conn), S2N_ERR_VERIFY_SIGNATURE);

        /* Clean up */
        free(cert_chain_pem);
        free(private_key_pem);
        EXPECT_SUCCESS(s2n_pkey_free(&client_conn->secure.server_public_key));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_in));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_out));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Client errors with wrong hash/signature algorithms */
    {
        /* Derive private/public keys and set connection variables */
        struct s2n_stuffer certificate_in, certificate_out;
        struct s2n_blob b;
        struct s2n_cert_chain_and_key *ecdsa_cert;
        char *cert_chain_pem;
        char *private_key_pem;
        s2n_pkey_type pkey_type;

        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(ecdsa_cert = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(ecdsa_cert, cert_chain_pem, private_key_pem));

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        client_conn->handshake_params.our_chain_and_key = ecdsa_cert;
        client_conn->secure.conn_sig_scheme = s2n_ecdsa_secp256r1_sha256;
        client_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

        b.data = (uint8_t *) cert_chain_pem;
        b.size = strlen(cert_chain_pem) + 1;
        EXPECT_SUCCESS(s2n_stuffer_write(&certificate_in, &b));

        EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));

        b.size = s2n_stuffer_data_available(&certificate_out);
        b.data = s2n_stuffer_raw_read(&certificate_out, b.size);
        EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&client_conn->secure.server_public_key, &pkey_type, &b));

        /* Hash initialization */
        EXPECT_SUCCESS(s2n_hash_init(&client_conn->handshake.sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&client_conn->handshake.sha256, hello, strlen((char *)hello)));

        /* send and receive with mismatched hash algs */
        EXPECT_SUCCESS(s2n_server_cert_verify_send(client_conn));

        client_conn->secure.conn_sig_scheme.hash_alg = S2N_HASH_SHA1;

        /* Reinitialize hash */
        EXPECT_SUCCESS(s2n_hash_init(&client_conn->handshake.sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&client_conn->handshake.sha256, hello, strlen((char *)hello)));

        EXPECT_FAILURE(s2n_server_cert_read_and_verify_signature(client_conn));

        /* send and receive with mismatched signature algs */
        client_conn->secure.conn_sig_scheme.hash_alg = S2N_HASH_SHA256;
        client_conn->secure.conn_sig_scheme.sig_alg = S2N_SIGNATURE_ANONYMOUS;
        client_conn->secure.conn_sig_scheme.iana_value = 0xFFFF;

        EXPECT_SUCCESS(s2n_hash_init(&client_conn->handshake.sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&client_conn->handshake.sha256, hello, strlen((char *)hello)));

        EXPECT_SUCCESS(s2n_server_cert_verify_send(client_conn));

        EXPECT_SUCCESS(s2n_hash_init(&client_conn->handshake.sha256, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&client_conn->handshake.sha256, hello, strlen((char *)hello)));

        EXPECT_FAILURE(s2n_server_cert_verify_recv(client_conn));

        /* Clean up */
        free(cert_chain_pem);
        free(private_key_pem);
        EXPECT_SUCCESS(s2n_pkey_free(&client_conn->secure.server_public_key));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_in));
        EXPECT_SUCCESS(s2n_stuffer_free(&certificate_out));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
}
