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

#include "crypto/s2n_rsa_pss.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_bitmap.h"

int s2n_parse_client_hello(struct s2n_connection *conn);

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
                        S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);
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

    /* Test: ClientHello extension ignored
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

        /* Write the certificate_authorities extension.
         * The client isn't allowed to write it, so use the server.
         */
        server->actual_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_extension_send(&s2n_cert_authorities_extension,
                server, input));

        /* Write the rest of the extensions */
        EXPECT_SUCCESS(s2n_stuffer_write(input, &client_hello->extensions.raw));

        /* Update the extensions size */
        EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&extensions_size));

        /* Server should be able to successfully receive the modified ClientHello */
        EXPECT_SUCCESS(s2n_client_hello_recv(server));
        EXPECT_TRUE(server->client_hello.parsed);
        EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS13);

        s2n_parsed_extension *extension = &server->client_hello.extensions.parsed_extensions[ca_ext_id];
        EXPECT_TRUE(extension->extension.size > 0);
        EXPECT_FALSE(extension->processed);
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

        /* Server sent extension */
        EXPECT_TRUE(S2N_CBIT_TEST(server->extension_requests_sent, ca_ext_id));
        EXPECT_FALSE(S2N_CBIT_TEST(server->extension_requests_received, ca_ext_id));

        /* Client received extension */
        EXPECT_FALSE(S2N_CBIT_TEST(client->extension_requests_sent, ca_ext_id));
        EXPECT_TRUE(S2N_CBIT_TEST(client->extension_requests_received, ca_ext_id));
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

    END_TEST();
}
