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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_cookie.h"
#include "tls/extensions/s2n_extension_type_lists.h"
#include "tls/extensions/s2n_server_key_share.h"
#include "tls/extensions/s2n_server_supported_versions.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* TLS 1.3 is not used by default */
    EXPECT_FALSE(s2n_use_default_tls13_config());

    /* TLS1.3 is not supported or configured by default */
    {
        /* Client does not support or configure TLS 1.3 */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_NOT_EQUAL(conn->client_protocol_version, S2N_TLS13);

            const struct s2n_security_policy *security_policy;
            EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
            EXPECT_FALSE(s2n_security_policy_supports_tls13(security_policy));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Server does not support or configure TLS 1.3 */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            EXPECT_NOT_EQUAL(conn->server_protocol_version, S2N_TLS13);

            const struct s2n_security_policy *security_policy;
            EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
            EXPECT_FALSE(s2n_security_policy_supports_tls13(security_policy));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    EXPECT_SUCCESS(s2n_enable_tls13_in_test());
    EXPECT_TRUE(s2n_use_default_tls13_config());

    /* Re-enabling has no effect */
    EXPECT_SUCCESS(s2n_enable_tls13_in_test());
    EXPECT_TRUE(s2n_use_default_tls13_config());

    /* If "enabled", TLS1.3 is supported and configured */
    {
        /* Client supports and configures TLS 1.3 */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_EQUAL(conn->client_protocol_version, S2N_TLS13);

            const struct s2n_security_policy *security_policy;
            EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
            EXPECT_TRUE(s2n_security_policy_supports_tls13(security_policy));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Server supports and configures TLS 1.3 */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            EXPECT_EQUAL(conn->server_protocol_version, S2N_TLS13);

            const struct s2n_security_policy *security_policy;
            EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
            EXPECT_TRUE(s2n_security_policy_supports_tls13(security_policy));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    EXPECT_FALSE(s2n_use_default_tls13_config());

    /* Re-disabling has no effect */
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    EXPECT_FALSE(s2n_use_default_tls13_config());

    /* Test s2n_is_valid_tls13_cipher() */
    {
        uint8_t value[2] = { 0x13, 0x01 };
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x13;
        value[1] = 0x02;
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x13;
        value[1] = 0x03;
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x13;
        value[1] = 0x04;
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x13;
        value[1] = 0x05;
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x13;
        value[1] = 0x06;
        EXPECT_FALSE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x13;
        value[1] = 0x00;
        EXPECT_FALSE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x12;
        value[1] = 0x01;
        EXPECT_FALSE(s2n_is_valid_tls13_cipher(value));

        EXPECT_FALSE(s2n_is_valid_tls13_cipher(s2n_dhe_rsa_with_3des_ede_cbc_sha.iana_value));
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(s2n_tls13_aes_128_gcm_sha256.iana_value));
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(s2n_tls13_aes_256_gcm_sha384.iana_value));
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(s2n_tls13_chacha20_poly1305_sha256.iana_value));
    }

    /* Server does not parse TLS 1.3 extensions unless TLS 1.3 negotiated */
    {
        s2n_extension_type_list *tls13_server_hello_extensions = NULL;
        EXPECT_SUCCESS(s2n_extension_type_list_get(S2N_EXTENSION_LIST_SERVER_HELLO_TLS13, &tls13_server_hello_extensions));
        EXPECT_NOT_NULL(tls13_server_hello_extensions);
        EXPECT_TRUE(tls13_server_hello_extensions->count > 0);

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(server_conn));

        struct s2n_stuffer extension_data = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension_data, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_str(&extension_data, "bad extension"));

        s2n_parsed_extensions_list parsed_extension_list = { 0 };
        for (size_t i = 0; i < tls13_server_hello_extensions->count; i++) {
            const s2n_extension_type *tls13_extension_type = tls13_server_hello_extensions->extension_types[i];
            s2n_extension_type_id extension_id;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(tls13_extension_type->iana_value, &extension_id));
            s2n_parsed_extension *parsed_extension = &parsed_extension_list.parsed_extensions[extension_id];

            /* Create parsed extension */
            parsed_extension->extension = extension_data.blob;
            parsed_extension->extension_type = tls13_extension_type->iana_value;

            server_conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_extension_process(tls13_extension_type, server_conn, &parsed_extension_list));

            /* Reuse processed extension */
            EXPECT_TRUE(parsed_extension->processed);
            parsed_extension->processed = false;

            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE(s2n_extension_process(tls13_extension_type, server_conn, &parsed_extension_list));
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension_data));
    };

    END_TEST();
    return 0;
}
