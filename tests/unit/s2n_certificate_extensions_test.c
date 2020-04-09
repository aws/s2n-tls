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

#include <string.h>
#include <stdio.h>
#include <s2n.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_certificate_extensions.h"

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

/* Modified test vectors from https://tools.ietf.org/html/rfc8448#section-3 */

/* with invalid certificate extension (supported version) on the end */
const char tls13_cert_invalid_ext_hex[] =
    "000001bb0001b03082" /* without 0b0001b9 header */
    "01ac30820115a003020102020102300d06092a8648"
    "86f70d01010b0500300e310c300a06035504031303"
    "727361301e170d3136303733303031323335395a17"
    "0d3236303733303031323335395a300e310c300a06"
    "03550403130372736130819f300d06092a864886f7"
    "0d010101050003818d0030818902818100b4bb498f"
    "8279303d980836399b36c6988c0c68de55e1bdb826"
    "d3901a2461eafd2de49a91d015abbc9a95137ace6c"
    "1af19eaa6af98c7ced43120998e187a80ee0ccb052"
    "4b1b018c3e0b63264d449a6d38e22a5fda43084674"
    "8030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193"
    "eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203"
    "010001a31a301830090603551d1304023000300b06"
    "03551d0f0404030205a0300d06092a864886f70d01"
    "010b05000381810085aad2a0e5b9276b908c65f73a"
    "7267170618a54c5f8a7b337d2df7a594365417f2ea"
    "e8f8a58c8f8172f9319cf36b7fd6c55b80f21a0301"
    "5156726096fd335e5e67f2dbf102702e608ccae6be"
    "c1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b"
    "1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8"
    "961229ac9187b42b4de10006002b00020103";

/* with single extension sent */
/* server can send empty status request extension from https://tools.ietf.org/html/rfc8446#section-4.4.2.1 */
const char tls13_cert_single_ext_hex[] =
    "000001b90001b03082" /* without 0b0001b9 header */
    "01ac30820115a003020102020102300d06092a8648"
    "86f70d01010b0500300e310c300a06035504031303"
    "727361301e170d3136303733303031323335395a17"
    "0d3236303733303031323335395a300e310c300a06"
    "03550403130372736130819f300d06092a864886f7"
    "0d010101050003818d0030818902818100b4bb498f"
    "8279303d980836399b36c6988c0c68de55e1bdb826"
    "d3901a2461eafd2de49a91d015abbc9a95137ace6c"
    "1af19eaa6af98c7ced43120998e187a80ee0ccb052"
    "4b1b018c3e0b63264d449a6d38e22a5fda43084674"
    "8030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193"
    "eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203"
    "010001a31a301830090603551d1304023000300b06"
    "03551d0f0404030205a0300d06092a864886f70d01"
    "010b05000381810085aad2a0e5b9276b908c65f73a"
    "7267170618a54c5f8a7b337d2df7a594365417f2ea"
    "e8f8a58c8f8172f9319cf36b7fd6c55b80f21a0301"
    "5156726096fd335e5e67f2dbf102702e608ccae6be"
    "c1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b"
    "1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8"
    "961229ac9187b42b4de1000400050000";


int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());

    /* Server send/receive certificate with TLS 1.3 and no extensions */
    {
        /* Initialize connections */
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS13;
        server_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

        /* Initialize cert chain */
        char *cert_chain_pem;
        char *private_key_pem;
        struct s2n_cert_chain_and_key *ecdsa_cert;

        EXPECT_NOT_NULL(ecdsa_cert = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(ecdsa_cert, cert_chain_pem, private_key_pem));

        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        server_conn->handshake_params.our_chain_and_key = ecdsa_cert;

        /* Send empty extensions */
        EXPECT_SUCCESS(s2n_server_cert_send(server_conn));
        EXPECT_TRUE(s2n_stuffer_data_available(&server_conn->handshake.io) > 0);

        /* Receive empty extensions */
        EXPECT_SUCCESS(s2n_server_cert_recv(server_conn));

        /* Clean up */
        free(cert_chain_pem);
        free(private_key_pem);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Client send/receive certificate with TLS 1.3 and no extensions */
    {
        /* Initialize connections */
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;

        /* Initialize cert chain */
        char *cert_chain_pem;
        char *private_key_pem;
        struct s2n_cert_chain_and_key *ecdsa_cert;

        EXPECT_NOT_NULL(ecdsa_cert = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(ecdsa_cert, cert_chain_pem, private_key_pem));

        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        client_conn->handshake_params.our_chain_and_key = ecdsa_cert;

        /* Send empty extensions */
        EXPECT_SUCCESS(s2n_client_cert_send(client_conn));
        EXPECT_TRUE(s2n_stuffer_data_available(&client_conn->handshake.io) > 0);

        /* Receive empty extensions */
        client_conn->x509_validator.skip_cert_validation = 1;
        EXPECT_SUCCESS(s2n_client_cert_recv(client_conn));

        /* Clean up */
        free(cert_chain_pem);
        free(private_key_pem);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Test this does not break happy path TLS 1.2 server send/recv */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;

        char *cert_chain_pem;
        char *private_key_pem;
        struct s2n_cert_chain_and_key *ecdsa_cert;

        EXPECT_NOT_NULL(ecdsa_cert = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(ecdsa_cert, cert_chain_pem, private_key_pem));

        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        server_conn->handshake_params.our_chain_and_key = ecdsa_cert;

        EXPECT_SUCCESS(s2n_server_cert_send(server_conn));
        EXPECT_TRUE(s2n_stuffer_data_available(&server_conn->handshake.io) > 0);

        server_conn->x509_validator.skip_cert_validation = 1;
        EXPECT_SUCCESS(s2n_server_cert_recv(server_conn));

        free(cert_chain_pem);
        free(private_key_pem);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Test TLS 1.2 client send/recv happy path does not break */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;

        char *cert_chain_pem;
        char *private_key_pem;
        struct s2n_cert_chain_and_key *ecdsa_cert;

        EXPECT_NOT_NULL(ecdsa_cert = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(ecdsa_cert, cert_chain_pem, private_key_pem));

        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        client_conn->handshake_params.our_chain_and_key = ecdsa_cert;

        EXPECT_SUCCESS(s2n_client_cert_send(client_conn));
        EXPECT_TRUE(s2n_stuffer_data_available(&client_conn->handshake.io) > 0);

        client_conn->x509_validator.skip_cert_validation = 1;
        EXPECT_SUCCESS(s2n_client_cert_recv(client_conn));

        free(cert_chain_pem);
        free(private_key_pem);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Test with TLS 1.3 and an extension sent */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        S2N_BLOB_FROM_HEX(tls13_cert, tls13_cert_single_ext_hex);
        EXPECT_SUCCESS(s2n_stuffer_write(&client_conn->handshake.io, &tls13_cert));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->handshake.io), 445);

        client_conn->x509_validator.skip_cert_validation = 1;
        EXPECT_SUCCESS(s2n_server_cert_recv(client_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->handshake.io), 0);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Test with TLS 1.3 and invalid kind of extension sent */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;

        /* Fill io stuffer with data for incorrect extension */
        S2N_BLOB_FROM_HEX(tls13_cert, tls13_cert_invalid_ext_hex);
        EXPECT_SUCCESS(s2n_stuffer_write(&client_conn->handshake.io, &tls13_cert));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->handshake.io), 447);

        client_conn->x509_validator.skip_cert_validation = 1;
        /* Verified it fails inside of extension parsing, but the error is masked by cert_untrusted */
        EXPECT_FAILURE_WITH_ERRNO(s2n_server_cert_recv(client_conn), S2N_ERR_CERT_UNTRUSTED);
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->handshake.io), 0);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* some arbitrary numbers for testing */
    #define OCSP_SIZE 5
    #define RAW_CERT_SIZE 7
    #define FAKE_CHAIN_SIZE 3
    #define SCT_LIST_SIZE 5

    /* Test OSCP sending with s2n_certificate_extensions_send() */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        s2n_stack_blob(ocsp_status, OCSP_SIZE, OCSP_SIZE);
        s2n_stack_blob(raw, RAW_CERT_SIZE, RAW_CERT_SIZE);
        struct s2n_cert_chain_and_key chain_and_key = {0};
        struct s2n_cert_chain cert_chain = {0};
        struct s2n_cert cert1 = {0};
        struct s2n_cert cert2 = {0};
        cert1.raw = raw;
        cert2.raw = raw;

        cert_chain.chain_size = FAKE_CHAIN_SIZE;
        chain_and_key.cert_chain = &cert_chain;
        cert_chain.head = &cert1;
        cert1.next = &cert2;
        chain_and_key.ocsp_status = ocsp_status;

        /* 2 certs in the chain, total extensions will occupy 4 bytes */
        EXPECT_EQUAL(s2n_certificate_total_extensions_size(server_conn, &chain_and_key), 4);

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1024));

        /* Empty certificate extensions occupies 2 bytes */
        EXPECT_SUCCESS(s2n_certificate_extensions_send_empty(&stuffer));
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 2);
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));

        /* Certificate extensions sending without extensions also occupies 2 bytes */
        EXPECT_SUCCESS(s2n_certificate_extensions_send(server_conn, &stuffer, &chain_and_key));
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 2);
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));

        /* Turn on the flags for OCSP */
        server_conn->status_type = S2N_STATUS_REQUEST_OCSP;

        /* Configure chain and key */
        server_conn->handshake_params.our_chain_and_key = &chain_and_key;

        const uint32_t EXPECTED_CERTIFICATE_EXTENSIONS_SIZE = 2 /* status request extensions header */
                                                            + 2 /* status request size */
                                                            + 1 /* status type */
                                                            + 3 /* ocsp header size */
                                                            + OCSP_SIZE; /* ocsp size; */
        const uint32_t EXPECTED_EXTENSIONS_SIZE = 4 /* u16 headers for 2 cert chains */
            + EXPECTED_CERTIFICATE_EXTENSIONS_SIZE;

        EXPECT_EQUAL(s2n_certificate_extensions_size(server_conn, &chain_and_key), EXPECTED_CERTIFICATE_EXTENSIONS_SIZE);
        EXPECT_EQUAL(s2n_certificate_total_extensions_size(server_conn, &chain_and_key), EXPECTED_EXTENSIONS_SIZE);
        EXPECT_SUCCESS(s2n_certificate_extensions_send(server_conn, &stuffer, &chain_and_key));

        uint16_t ocsp_extension_size = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &ocsp_extension_size));
        EXPECT_EQUAL(ocsp_extension_size, s2n_stuffer_data_available(&stuffer));
        EXPECT_EQUAL(ocsp_extension_size, EXPECTED_EXTENSIONS_SIZE - 4); /* remove the overall extensions header overheads */

        /* copy remaining stuffer contents into a extension blob */
        struct s2n_blob extension_blob = {0};
        extension_blob.size = s2n_stuffer_data_available(&stuffer);
        extension_blob.data = s2n_stuffer_raw_read(&stuffer, extension_blob.size);
        EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));

        /* Test that s2n_certificate_extensions_parse() can read the extension blob contents */
        EXPECT_SUCCESS(s2n_certificate_extensions_parse(server_conn, &extension_blob));

        /* The current behaviour does not send OCSP stapling in client mode */
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->status_type = S2N_STATUS_REQUEST_OCSP;
        client_conn->handshake_params.our_chain_and_key = &chain_and_key;

        /* Test a failure case */
        struct s2n_stuffer small_stuffer;
        EXPECT_SUCCESS(s2n_stuffer_alloc(&small_stuffer, 5));
        EXPECT_FAILURE(s2n_certificate_extensions_send(server_conn, &small_stuffer, &chain_and_key));
        EXPECT_SUCCESS(s2n_stuffer_free(&small_stuffer));

        EXPECT_EQUAL(s2n_certificate_extensions_size(client_conn, &chain_and_key), 0);

        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
        EXPECT_SUCCESS(s2n_certificate_extensions_send(client_conn, &stuffer, &chain_and_key));
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 2); /* 2 bytes for empty extension */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Test Certificate Transparency / Server Certificate Timestamp Stapling */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        s2n_stack_blob(sct_list, SCT_LIST_SIZE, SCT_LIST_SIZE);
        s2n_stack_blob(raw, RAW_CERT_SIZE, RAW_CERT_SIZE);
        struct s2n_cert_chain_and_key chain_and_key = {0};
        struct s2n_cert_chain cert_chain = {0};
        struct s2n_cert cert1 = {0};
        struct s2n_cert cert2 = {0};
        cert1.raw = raw;
        cert2.raw = raw;

        cert_chain.chain_size = FAKE_CHAIN_SIZE;
        chain_and_key.cert_chain = &cert_chain;
        cert_chain.head = &cert1;
        cert1.next = &cert2;
        chain_and_key.sct_list = sct_list;

        /* 2 certs in the chain, total extensions will occupy 4 bytes */
        EXPECT_EQUAL(s2n_certificate_total_extensions_size(server_conn, &chain_and_key), 4);

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1024));

        /* Empty certificate extensions occupies 2 bytes */
        EXPECT_SUCCESS(s2n_certificate_extensions_send_empty(&stuffer));
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 2);
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));

        /* Certificate extensions sending without extensions also occupies 2 bytes */
        EXPECT_SUCCESS(s2n_certificate_extensions_send(server_conn, &stuffer, &chain_and_key));
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 2);
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));

        /* Turn on the flags for Certificate Transparency */
        server_conn->ct_level_requested = S2N_CT_SUPPORT_REQUEST;
        server_conn->handshake_params.our_chain_and_key = &chain_and_key;

        const uint32_t EXPECTED_CERTIFICATE_EXTENSIONS_SIZE = 2 /* sct list extensions header */
                                                            + 2 /* sct list size */
                                                            + SCT_LIST_SIZE; /* cert_transparency size; */
        const uint32_t EXPECTED_EXTENSIONS_SIZE = 4 /* u16 headers for 2 cert chains */
            + EXPECTED_CERTIFICATE_EXTENSIONS_SIZE;

        EXPECT_EQUAL(s2n_certificate_extensions_size(server_conn, &chain_and_key), EXPECTED_CERTIFICATE_EXTENSIONS_SIZE);
        EXPECT_EQUAL(s2n_certificate_total_extensions_size(server_conn, &chain_and_key), EXPECTED_EXTENSIONS_SIZE);
        EXPECT_SUCCESS(s2n_certificate_extensions_send(server_conn, &stuffer, &chain_and_key));

        uint16_t cert_transparency_extension_size = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &cert_transparency_extension_size));
        EXPECT_EQUAL(cert_transparency_extension_size, s2n_stuffer_data_available(&stuffer));
        EXPECT_EQUAL(cert_transparency_extension_size, EXPECTED_EXTENSIONS_SIZE - 4); /* remove the overall extensions header overheads */

        /* copy remaining stuffer contents into a extension blob */
        struct s2n_blob extension_blob = {0};
        extension_blob.size = s2n_stuffer_data_available(&stuffer);
        extension_blob.data = s2n_stuffer_raw_read(&stuffer, extension_blob.size);
        EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));

        /* Test that s2n_certificate_extensions_parse() can read the contents */
        EXPECT_SUCCESS(s2n_certificate_extensions_parse(server_conn, &extension_blob));

        /* Test a failure case */
        struct s2n_stuffer small_stuffer;
        EXPECT_SUCCESS(s2n_stuffer_alloc(&small_stuffer, 5));
        EXPECT_FAILURE(s2n_certificate_extensions_send(server_conn, &small_stuffer, &chain_and_key));
        EXPECT_SUCCESS(s2n_stuffer_free(&small_stuffer));

        /* The current behaviour does not send cert_transparency stapling in client mode */
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->ct_level_requested = S2N_CT_SUPPORT_REQUEST;
        client_conn->handshake_params.our_chain_and_key = &chain_and_key;

        EXPECT_EQUAL(s2n_certificate_extensions_size(client_conn, &chain_and_key), 0);

        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
        EXPECT_SUCCESS(s2n_certificate_extensions_send(client_conn, &stuffer, &chain_and_key));
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 2); /* 2 bytes for empty extension */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Test Server OCSP and SCT Stapling */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        s2n_stack_blob(ocsp_status, OCSP_SIZE, OCSP_SIZE);
        s2n_stack_blob(sct_list, SCT_LIST_SIZE, SCT_LIST_SIZE);
        s2n_stack_blob(raw, RAW_CERT_SIZE, RAW_CERT_SIZE);
        struct s2n_cert_chain_and_key chain_and_key = {0};
        struct s2n_cert_chain cert_chain = {0};
        struct s2n_cert cert1 = {0};
        struct s2n_cert cert2 = {0};
        cert1.raw = raw;
        cert2.raw = raw;

        cert_chain.chain_size = FAKE_CHAIN_SIZE;
        chain_and_key.cert_chain = &cert_chain;
        cert_chain.head = &cert1;
        cert1.next = &cert2;
        chain_and_key.sct_list = sct_list;
        chain_and_key.ocsp_status = ocsp_status;

        /* 2 certs in the chain, total extensions will occupy 4 bytes */
        EXPECT_EQUAL(s2n_certificate_total_extensions_size(server_conn, &chain_and_key), 4);

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1024));

        /* Certificate extensions sending without extensions also occupies 2 bytes */
        EXPECT_SUCCESS(s2n_certificate_extensions_send(server_conn, &stuffer, &chain_and_key));
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 2);
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));

        /* Turn on the flags for OCSP and Certificate Transparency */
        server_conn->status_type = S2N_STATUS_REQUEST_OCSP;
        server_conn->ct_level_requested = S2N_CT_SUPPORT_REQUEST;
        server_conn->handshake_params.our_chain_and_key = &chain_and_key;

        const uint32_t EXPECTED_CERTIFICATE_EXTENSIONS_SIZE = 2 /* status request extensions header */
                                                            + 2 /* status request size */
                                                            + 1 /* status type */
                                                            + 3 /* ocsp header size */
                                                            + OCSP_SIZE
                                                            + 2 /* sct list extensions header */
                                                            + 2 /* sct list size */
                                                            + SCT_LIST_SIZE; /* cert_transparency size; */
        const uint32_t EXPECTED_EXTENSIONS_SIZE = 4 /* u16 headers for 2 cert chains */
            + EXPECTED_CERTIFICATE_EXTENSIONS_SIZE;

        EXPECT_EQUAL(s2n_certificate_extensions_size(server_conn, &chain_and_key), EXPECTED_CERTIFICATE_EXTENSIONS_SIZE);
        EXPECT_EQUAL(s2n_certificate_total_extensions_size(server_conn, &chain_and_key), EXPECTED_EXTENSIONS_SIZE);
        EXPECT_SUCCESS(s2n_certificate_extensions_send(server_conn, &stuffer, &chain_and_key));

        uint16_t cert_transparency_extension_size = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &cert_transparency_extension_size));
        EXPECT_EQUAL(cert_transparency_extension_size, s2n_stuffer_data_available(&stuffer));
        EXPECT_EQUAL(cert_transparency_extension_size, EXPECTED_EXTENSIONS_SIZE - 4); /* remove the overall extensions header overheads */

        /* copy remaining stuffer contents into a extension blob */
        struct s2n_blob extension_blob = {0};
        extension_blob.size = s2n_stuffer_data_available(&stuffer);
        extension_blob.data = s2n_stuffer_raw_read(&stuffer, extension_blob.size);
        EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));

        /* Test that s2n_certificate_extensions_parse() can read the contents */
        EXPECT_SUCCESS(s2n_certificate_extensions_parse(server_conn, &extension_blob));

        /* Test a failure case */
        struct s2n_stuffer small_stuffer;
        EXPECT_SUCCESS(s2n_stuffer_alloc(&small_stuffer, 5));
        EXPECT_FAILURE(s2n_certificate_extensions_send(server_conn, &small_stuffer, &chain_and_key));
        EXPECT_SUCCESS(s2n_stuffer_free(&small_stuffer));

        /* The current behaviour does not send cert_transparency stapling in client mode */
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->ct_level_requested = S2N_CT_SUPPORT_REQUEST;
        client_conn->handshake_params.our_chain_and_key = &chain_and_key;

        EXPECT_EQUAL(s2n_certificate_extensions_size(client_conn, &chain_and_key), 0);

        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
        EXPECT_SUCCESS(s2n_certificate_extensions_send(client_conn, &stuffer, &chain_and_key));
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 2); /* 2 bytes for empty extension */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();

    return 0;
}
