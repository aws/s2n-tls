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

#include "tls/extensions/s2n_cert_authorities.h"

#include <openssl/x509.h>

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_libcrypto.h"
#include "crypto/s2n_openssl_x509.h"
#include "crypto/s2n_rsa_pss.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_bitmap.h"

int s2n_parse_client_hello(struct s2n_connection *conn);

/* Build a certificate_authorities blob (a sequence of uint16 length ||
 * DER X509_NAME entries) containing the subject names of the certificates in
 * the given chain at the specified indices (0 == leaf). */
static S2N_RESULT s2n_test_build_ca_names(struct s2n_cert_chain_and_key *chain,
        const size_t *indices, size_t indices_count, struct s2n_blob *out)
{
    struct s2n_stuffer stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&stuffer, 256));

    for (size_t i = 0; i < indices_count; i++) {
        struct s2n_cert *cert = chain->cert_chain->head;
        for (size_t skip = 0; skip < indices[i]; skip++) {
            RESULT_ENSURE_REF(cert);
            cert = cert->next;
        }
        RESULT_ENSURE_REF(cert);

        DEFER_CLEANUP(X509 *x509 = NULL, X509_free_pointer);
        RESULT_GUARD(s2n_openssl_x509_parse(&cert->raw, &x509));
        X509_NAME *subject = X509_get_subject_name(x509);
        RESULT_ENSURE_REF(subject);
        const uint8_t *name = NULL;
        size_t name_size = 0;
        RESULT_GUARD_OSSL(X509_NAME_get0_der(subject, &name, &name_size), S2N_ERR_SAFETY);

        RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(&stuffer, name_size));
        RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(&stuffer, name, name_size));
    }

    RESULT_GUARD_POSIX(s2n_stuffer_extract_blob(&stuffer, out));
    RESULT_GUARD_POSIX(s2n_stuffer_free(&stuffer));
    return S2N_RESULT_OK;
}

/* Count the number of certificates in a TLS1.2-format Certificate message
 * body written by s2n_send_cert_chain (uint24 total || repeated uint24 len ||
 * cert bytes). */
static S2N_RESULT s2n_test_count_certs(struct s2n_stuffer *stuffer, size_t *count)
{
    *count = 0;
    uint32_t total_size = 0;
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint24(stuffer, &total_size));
    RESULT_ENSURE_EQ(total_size, s2n_stuffer_data_available(stuffer));
    while (s2n_stuffer_data_available(stuffer) > 0) {
        uint32_t cert_size = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint24(stuffer, &cert_size));
        RESULT_GUARD_POSIX(s2n_stuffer_skip_read(stuffer, cert_size));
        (*count)++;
    }
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *cert_chain = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&cert_chain,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    s2n_extension_type_id temp_id = s2n_unsupported_extension;
    EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(
            s2n_cert_authorities_extension.iana_value, &temp_id));
    const s2n_extension_type_id ca_ext_id = temp_id;

    /* Test: awslc should always support loading from the trust store */
    if (s2n_libcrypto_is_awslc()) {
        EXPECT_TRUE(s2n_cert_authorities_supported_from_trust_store());
    }

    /* Test: s2n_config_set_cert_authorities_from_trust_store */
    {
        /* Test: Safety */
        {
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_config_set_cert_authorities_from_trust_store(NULL),
                    S2N_ERR_NULL);
        };

        /* Test: fails if not supported */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                    S2N_ECDSA_P512_CERT_CHAIN, NULL));

            if (s2n_cert_authorities_supported_from_trust_store()) {
                EXPECT_SUCCESS(s2n_config_set_cert_authorities_from_trust_store(config));
                EXPECT_NOT_EQUAL(config->cert_authorities.size, 0);
            } else {
                EXPECT_FAILURE_WITH_ERRNO(
                        s2n_config_set_cert_authorities_from_trust_store(config),
                        S2N_ERR_API_UNSUPPORTED_BY_LIBCRYPTO);
                EXPECT_EQUAL(config->cert_authorities.size, 0);
            }
        };

        /* Test: not allowed with system trust store */
        {
            /* s2n_config_new configures the default trust store */
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);

            /* Fails with default system trust store */
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_config_set_cert_authorities_from_trust_store(config),
                    S2N_ERR_INVALID_STATE);
            EXPECT_EQUAL(config->cert_authorities.size, 0);

            /* Succeeds again after wiping trust store */
            EXPECT_SUCCESS(s2n_config_wipe_trust_store(config));
            EXPECT_SUCCESS(s2n_config_set_cert_authorities_from_trust_store(config));
            EXPECT_EQUAL(config->cert_authorities.size, 0);
        };

        /* Test: empty trust store */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_cert_authorities_from_trust_store(config));
            EXPECT_EQUAL(config->cert_authorities.size, 0);
        };

        /* Test: too many CAs in trust store */
        if (s2n_cert_authorities_supported_from_trust_store()) {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            /* This is just a copy of the default trust store from an Amazon Linux instance */
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_TEST_TRUST_STORE, NULL));

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_config_set_cert_authorities_from_trust_store(config),
                    S2N_ERR_TOO_MANY_CAS);
            EXPECT_EQUAL(config->cert_authorities.size, 0);
        };
    };

    /* Test: s2n_certificate_authorities_extension.send */
    {
        /* Test: writes whatever CA data is available */
        {
            const uint8_t ca_data[] = "these are my CAs";

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_alloc(&config->cert_authorities, sizeof(ca_data)));
            EXPECT_MEMCPY_SUCCESS(config->cert_authorities.data, ca_data, sizeof(ca_data));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->actual_protocol_version = S2N_TLS13;

            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            EXPECT_SUCCESS(s2n_cert_authorities_extension.send(conn, &output));

            uint16_t size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&output, &size));
            EXPECT_EQUAL(size, sizeof(ca_data));
            EXPECT_EQUAL(size, s2n_stuffer_data_available(&output));

            uint8_t *data = s2n_stuffer_raw_read(&output, size);
            EXPECT_NOT_NULL(data);
            EXPECT_BYTEARRAY_EQUAL(data, ca_data, sizeof(ca_data));
        };
    };

    /* Test: s2n_certificate_authorities_extension.should_send */
    {
        /* Test: do not send for TLS1.2 */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_alloc(&config->cert_authorities, 10));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_extension_send(&s2n_cert_authorities_extension,
                    conn, &output));
            EXPECT_EQUAL(s2n_stuffer_data_available(&output), 0);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_extension_send(&s2n_cert_authorities_extension,
                    conn, &output));
            EXPECT_NOT_EQUAL(s2n_stuffer_data_available(&output), 0);
        };

        /* Test: do not send if no CA data set */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_FALSE(s2n_cert_authorities_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_alloc(&config->cert_authorities, 10));
            EXPECT_TRUE(s2n_cert_authorities_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_free(&config->cert_authorities));
            EXPECT_FALSE(s2n_cert_authorities_extension.should_send(conn));
        };
    };

    /* Test: ClientHello extension sent by client but ignored by server
     *
     * The client now sends the certificate_authorities extension in the
     * ClientHello when CA data is configured. The server accepts the
     * ClientHello but does not process the extension, since s2n-tls only
     * reads certificate_authorities from a server's CertificateRequest.
     *
     *= https://www.rfc-editor.org/rfc/rfc8446#section-4.2.4
     *= type=test
     *# The client MAY send the "certificate_authorities" extension in the
     *# ClientHello message.
     */
    if (s2n_is_tls13_fully_supported()) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert_chain));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_alloc(&config->cert_authorities, 10));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        EXPECT_SUCCESS(s2n_client_hello_send(client));
        EXPECT_SUCCESS(s2n_parse_client_hello(client));
        struct s2n_client_hello *client_hello = &client->client_hello;

        /* The client wrote the certificate_authorities extension itself, so it
         * is present in the ClientHello's own extensions. */
        s2n_parsed_extension *client_extension =
                &client_hello->extensions.parsed_extensions[ca_ext_id];
        EXPECT_EQUAL(client_extension->extension_type,
                s2n_cert_authorities_extension.iana_value);
        EXPECT_TRUE(client_extension->extension.size > 0);

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));
        struct s2n_stuffer *input = &server->handshake.io;

        /* Copy ClientHello, except extensions */
        size_t size_without_extensions = client_hello->raw_message.size
                - client_hello->extensions.raw.size
                - sizeof(uint16_t) /* Extensions size */;
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(input,
                client_hello->raw_message.data, size_without_extensions));

        /* Save space for new extensions size */
        struct s2n_stuffer_reservation extensions_size = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(input, &extensions_size));

        /* Write the client's extensions as-is. The client already includes the
         * certificate_authorities extension, so no manual injection is needed. */
        EXPECT_SUCCESS(s2n_stuffer_write(input, &client_hello->extensions.raw));

        /* Update the extensions size */
        EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&extensions_size));

        /* Server should be able to successfully receive the ClientHello */
        EXPECT_SUCCESS(s2n_client_hello_recv(server));
        EXPECT_TRUE(server->client_hello.parsed);
        EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS13);

        /* Server received the extension. It is recognized as part of the
         * ClientHello extension list, so it is marked processed, but its recv
         * handler is a no-op on the server side (s2n-tls only reads
         * certificate_authorities from a server's CertificateRequest). */
        s2n_parsed_extension *extension = &server->client_hello.extensions.parsed_extensions[ca_ext_id];
        EXPECT_TRUE(extension->extension.size > 0);
        EXPECT_TRUE(extension->processed);
        EXPECT_EQUAL(extension->extension_type, s2n_cert_authorities_extension.iana_value);
    };

    /* Self-talk test: CertificateRequest extension parsed
     *
     *= https://www.rfc-editor.org/rfc/rfc8446#section-4.2.4
     *= type=test
     *# The server MAY send it in the CertificateRequest message.
     **/
    if (s2n_is_tls13_fully_supported()) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert_chain));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_OPTIONAL));
        EXPECT_SUCCESS(s2n_alloc(&config->cert_authorities, 10));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
        EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS13);
        EXPECT_TRUE(IS_CLIENT_AUTH_HANDSHAKE(server));

        /* Both peers advertise certificate_authorities: the client in its
         * ClientHello and the server in its CertificateRequest. */

        /* Server sent it in the CertificateRequest and received the client's
         * ClientHello copy. */
        EXPECT_TRUE(S2N_CBIT_TEST(server->extension_requests_sent, ca_ext_id));
        EXPECT_TRUE(S2N_CBIT_TEST(server->extension_requests_received, ca_ext_id));

        /* Client sent it in the ClientHello and received the server's
         * CertificateRequest copy. */
        EXPECT_TRUE(S2N_CBIT_TEST(client->extension_requests_sent, ca_ext_id));
        EXPECT_TRUE(S2N_CBIT_TEST(client->extension_requests_received, ca_ext_id));
    };

    /* Self-talk test: server selects its certificate chain based on the CA
     * names advertised by the client in the certificate_authorities extension,
     * but only when more than one certificate chain is configured. */
    if (s2n_is_tls13_fully_supported() && s2n_cert_authorities_supported_from_trust_store()) {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *rsa_chain = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_chain,
                S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY));
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain,
                S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));

        /* Build a client config that advertises the CA names for a given cert
         * chain file, so the server can match against it. */
        struct {
            const char *ca_cert_file;
            struct s2n_cert_chain_and_key *expected_chain;
        } test_cases[] = {
            { .ca_cert_file = S2N_ECDSA_P384_PKCS1_CERT_CHAIN, .expected_chain = ecdsa_chain },
            { .ca_cert_file = S2N_RSA_2048_PKCS1_CERT_CHAIN, .expected_chain = rsa_chain },
        };

        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            /* Server: both an RSA and an ECDSA chain are configured. */
            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(server_config));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_chain));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_chain));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));
            EXPECT_EQUAL(s2n_config_get_num_default_certs(server_config), 2);

            /* Client: trusts both chains (so validation succeeds), but only
             * advertises the CA names of the chain for this test case. */
            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new_minimal(),
                    s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config,
                    test_cases[i].ca_cert_file, NULL));
            EXPECT_SUCCESS(s2n_config_set_cert_authorities_from_trust_store(client_config));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
            EXPECT_NOT_EQUAL(client_config->cert_authorities.size, 0);

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
            EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS13);

            /* The server received the extension and picked the chain whose CA
             * names the client advertised. */
            EXPECT_TRUE(S2N_CBIT_TEST(server->extension_requests_received, ca_ext_id));
            EXPECT_EQUAL(server->handshake_params.our_chain_and_key, test_cases[i].expected_chain);
        }
    };

    /* Self-talk test: with a single certificate chain configured, the server
     * ignores the certificate_authorities extension and always sends its one
     * chain, even if the advertised CA names do not match it. */
    if (s2n_is_tls13_fully_supported() && s2n_cert_authorities_supported_from_trust_store()) {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain,
                S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(server_config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_chain));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));
        EXPECT_EQUAL(s2n_config_get_num_default_certs(server_config), 1);

        /* Client advertises the CA names of a DIFFERENT chain (RSA). */
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new_minimal(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config,
                S2N_ECDSA_P384_PKCS1_CERT_CHAIN, NULL));
        EXPECT_SUCCESS(s2n_config_set_cert_authorities_from_trust_store(client_config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
        EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS13);

        /* With a single chain, the server does not even store the advertised
         * CA names, and it sends its only chain. */
        EXPECT_EQUAL(server->cert_authorities.size, 0);
        EXPECT_EQUAL(server->handshake_params.our_chain_and_key, ecdsa_chain);
    };

    /* Test: s2n_send_cert_chain omits CA certificates that the client already
     * advertised in the certificate_authorities extension. The RSA test chain
     * contains three certs: leaf (index 0), intermediate (1), and root (2). */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *rsa_chain = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_chain,
                S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY));

        /* Sanity check: the full chain has three certificates. */
        size_t chain_cert_count = 0;
        for (struct s2n_cert *c = rsa_chain->cert_chain->head; c != NULL; c = c->next) {
            chain_cert_count++;
        }
        EXPECT_EQUAL(chain_cert_count, 3);

        /* Control: a server that received no CA names sends the full chain. */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->handshake_params.our_chain_and_key = rsa_chain;
            conn->actual_protocol_version = S2N_TLS12;

            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_send_cert_chain(conn, &out, rsa_chain));

            size_t count = 0;
            EXPECT_OK(s2n_test_count_certs(&out, &count));
            EXPECT_EQUAL(count, 3);
        };

        /* Client advertised the intermediate and root: the server sends only
         * the leaf. Even though the leaf's own subject is not advertised, this
         * confirms the intermediate and root are pruned. */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->handshake_params.our_chain_and_key = rsa_chain;
            conn->actual_protocol_version = S2N_TLS12;

            size_t indices[] = { 1, 2 };
            EXPECT_OK(s2n_test_build_ca_names(rsa_chain, indices,
                    s2n_array_len(indices), &conn->cert_authorities));

            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_send_cert_chain(conn, &out, rsa_chain));

            size_t count = 0;
            EXPECT_OK(s2n_test_count_certs(&out, &count));
            EXPECT_EQUAL(count, 1);
        };

        /* Client advertised only the intermediate: the server prunes the
         * intermediate but still sends the leaf and the root. */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->handshake_params.our_chain_and_key = rsa_chain;
            conn->actual_protocol_version = S2N_TLS12;

            size_t indices[] = { 1 };
            EXPECT_OK(s2n_test_build_ca_names(rsa_chain, indices,
                    s2n_array_len(indices), &conn->cert_authorities));

            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_send_cert_chain(conn, &out, rsa_chain));

            size_t count = 0;
            EXPECT_OK(s2n_test_count_certs(&out, &count));
            EXPECT_EQUAL(count, 2);
        };

        /* The leaf is never pruned, even if the client advertised the leaf's
         * own subject. Advertising all three subjects still sends the leaf. */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->handshake_params.our_chain_and_key = rsa_chain;
            conn->actual_protocol_version = S2N_TLS12;

            size_t indices[] = { 0, 1, 2 };
            EXPECT_OK(s2n_test_build_ca_names(rsa_chain, indices,
                    s2n_array_len(indices), &conn->cert_authorities));

            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_send_cert_chain(conn, &out, rsa_chain));

            size_t count = 0;
            EXPECT_OK(s2n_test_count_certs(&out, &count));
            EXPECT_EQUAL(count, 1);
        };

        /* A client does NOT prune its own certificate chain: pruning is
         * server-only. A client connection with advertised CA names still
         * sends its full chain. */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            conn->handshake_params.our_chain_and_key = rsa_chain;
            conn->actual_protocol_version = S2N_TLS12;

            size_t indices[] = { 1, 2 };
            EXPECT_OK(s2n_test_build_ca_names(rsa_chain, indices,
                    s2n_array_len(indices), &conn->cert_authorities));

            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_send_cert_chain(conn, &out, rsa_chain));

            size_t count = 0;
            EXPECT_OK(s2n_test_count_certs(&out, &count));
            EXPECT_EQUAL(count, 3);
        };
    };

    /* Known value test: compare our extension to openssl s_server */
    if (s2n_is_rsa_pss_certs_supported() && s2n_cert_authorities_supported_from_trust_store()) {
        /* clang-format off */
        const struct {
            const char *cert_name;
            uint8_t expected_bytes_size;
            uint8_t expected_bytes[1000];
        } test_cases[] = {
            {
                .cert_name = S2N_RSA_PSS_2048_SHA256_LEAF_CERT,
                .expected_bytes_size = 32,
                .expected_bytes = {
                    0x00, 0x2f, 0x00, 0x1c, 0x00, 0x1a, 0x00, 0x18,
                    0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03,
                    0x55, 0x04, 0x03, 0x0c, 0x0b, 0x65, 0x78, 0x61,
                    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
                },
            },
            {
                .cert_name = S2N_ECDSA_P512_CERT_CHAIN,
                .expected_bytes_size = 107,
                .expected_bytes = {
                    0x00, 0x2f, 0x00, 0x67, 0x00, 0x65, 0x00, 0x63,
                    0x30, 0x61, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
                    0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
                    0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08,
                    0x0c, 0x02, 0x57, 0x41, 0x31, 0x10, 0x30, 0x0e,
                    0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x07, 0x53,
                    0x65, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x31, 0x0f,
                    0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
                    0x06, 0x41, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x31,
                    0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b,
                    0x0c, 0x03, 0x73, 0x32, 0x6e, 0x31, 0x14, 0x30,
                    0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b,
                    0x73, 0x32, 0x6e, 0x54, 0x65, 0x73, 0x74, 0x43,
                    0x65, 0x72, 0x74
                },
            },
            {
                .cert_name = S2N_RSA_2048_SHA256_URI_SANS_CERT,
                .expected_bytes_size = 192,
                .expected_bytes = {
                    0x00, 0x2f, 0x00, 0xbc, 0x00, 0xba, 0x00, 0x53,
                    0x30, 0x51, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
                    0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
                    0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08,
                    0x0c, 0x02, 0x57, 0x41, 0x31, 0x0f, 0x30, 0x0d,
                    0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x41,
                    0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x31, 0x0c, 0x30,
                    0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03,
                    0x73, 0x32, 0x6e, 0x31, 0x16, 0x30, 0x14, 0x06,
                    0x03, 0x55, 0x04, 0x03, 0x0c, 0x0d, 0x73, 0x32,
                    0x6e, 0x54, 0x65, 0x73, 0x74, 0x53, 0x65, 0x72,
                    0x76, 0x65, 0x72, 0x00, 0x63, 0x30, 0x61, 0x31,
                    0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
                    0x13, 0x02, 0x55, 0x53, 0x31, 0x0b, 0x30, 0x09,
                    0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x57,
                    0x41, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
                    0x04, 0x07, 0x0c, 0x07, 0x53, 0x65, 0x61, 0x74,
                    0x74, 0x6c, 0x65, 0x31, 0x0f, 0x30, 0x0d, 0x06,
                    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x41, 0x6d,
                    0x61, 0x7a, 0x6f, 0x6e, 0x31, 0x0c, 0x30, 0x0a,
                    0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x73,
                    0x32, 0x6e, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03,
                    0x55, 0x04, 0x03, 0x0c, 0x0b, 0x73, 0x32, 0x6e,
                    0x54, 0x65, 0x73, 0x74, 0x52, 0x6f, 0x6f, 0x74
                },
            },
            {
                .cert_name = S2N_RSA_2048_PKCS1_CERT_CHAIN,
                .expected_bytes_size = 94,
                .expected_bytes = {
                    0x00, 0x2f, 0x00, 0x5a, 0x00, 0x58, 0x00, 0x1a,
                    0x30, 0x18, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03,
                    0x55, 0x04, 0x03, 0x0c, 0x0d, 0x73, 0x32, 0x6e,
                    0x54, 0x65, 0x73, 0x74, 0x53, 0x65, 0x72, 0x76,
                    0x65, 0x72, 0x00, 0x20, 0x30, 0x1e, 0x31, 0x1c,
                    0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
                    0x13, 0x73, 0x32, 0x6e, 0x54, 0x65, 0x73, 0x74,
                    0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64,
                    0x69, 0x61, 0x74, 0x65, 0x00, 0x18, 0x30, 0x16,
                    0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04,
                    0x03, 0x0c, 0x0b, 0x73, 0x32, 0x6e, 0x54, 0x65,
                    0x73, 0x74, 0x52, 0x6f, 0x6f, 0x74
                },
            },
        };
        /* clang-format on */

        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(),
                    s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                    test_cases[i].cert_name, NULL));

            EXPECT_SUCCESS(s2n_config_set_cert_authorities_from_trust_store(config));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->actual_protocol_version = S2N_TLS13;

            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            EXPECT_SUCCESS(s2n_extension_send(&s2n_cert_authorities_extension,
                    conn, &output));

            size_t output_size = s2n_stuffer_data_available(&output);
            EXPECT_EQUAL(test_cases[i].expected_bytes_size, output_size);

            uint8_t *output_bytes = s2n_stuffer_raw_read(&output, output_size);
            EXPECT_NOT_NULL(output_bytes);
            EXPECT_BYTEARRAY_EQUAL(test_cases[i].expected_bytes, output_bytes, output_size);
        }
    };

    /* Safety Test: s2n_certificate_request_get_ca_list */
    {
        EXPECT_NULL(s2n_certificate_request_get_ca_list(NULL));
    };

    /* Safety Test: s2n_certificate_request_set_certificate */
    {
        /* Note: NULL for the 2nd argument is tested in s2n_mutual_auth. */
        EXPECT_FAILURE_WITH_ERRNO(s2n_certificate_request_set_certificate(NULL, NULL), S2N_ERR_INVALID_ARGUMENT);
    };

    /* Safety Test: s2n_certificate_authority_list_has_next */
    {
        EXPECT_FALSE(s2n_certificate_authority_list_has_next(NULL));
    };

    END_TEST();
}
