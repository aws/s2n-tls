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
     *= https://tools.ietf.org/rfc/rfc8446#section-4.2.4
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
     *= https://tools.ietf.org/rfc/rfc8446#section-4.2.4
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

    END_TEST();
}
