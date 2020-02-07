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

#include <stdint.h>

#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/extensions/s2n_client_signature_algorithms.h"
#include "tls/s2n_client_extensions.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test that recv can parse send */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);

        struct s2n_stuffer io;
        s2n_stuffer_alloc(&io, s2n_extensions_client_signature_algorithms_size(client_conn));

        EXPECT_SUCCESS(s2n_extensions_client_signature_algorithms_send(client_conn, &io));

        uint16_t extension_type;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&io, &extension_type));
        EXPECT_EQUAL(extension_type, TLS_EXTENSION_SIGNATURE_ALGORITHMS);

        uint16_t extension_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&io, &extension_size));
        EXPECT_EQUAL(extension_size, s2n_stuffer_data_available(&io));

        EXPECT_SUCCESS(s2n_extensions_client_signature_algorithms_recv(server_conn, &io));
        EXPECT_EQUAL(s2n_stuffer_data_available(&io), 0);

        EXPECT_EQUAL(server_conn->handshake_params.client_sig_hash_algs.len,
                s2n_supported_sig_schemes_count(client_conn));

        s2n_stuffer_free(&io);
        s2n_connection_free(client_conn);
        s2n_connection_free(server_conn);
    }

    {
        /* Test that unknown TLS_EXTENSION_SIGNATURE_ALGORITHMS values are ignored and negotiation fails */
        struct s2n_sig_scheme_list sig_hash_algs = {
            .iana_list = { 0xFF01, 0xFFFF },
            .len = 2,
        };
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer signature_algorithms_extension;
        EXPECT_SUCCESS(s2n_stuffer_alloc(&signature_algorithms_extension, 2 + (sig_hash_algs.len * 2)));
        GUARD(s2n_stuffer_write_uint16(&signature_algorithms_extension, sig_hash_algs.len * 2));
        for (int i = 0; i < sig_hash_algs.len; i++) {
            GUARD(s2n_stuffer_write_uint16(&signature_algorithms_extension, sig_hash_algs.iana_list[i]));
        }

        struct s2n_array *parsed_extensions = s2n_array_new(sizeof(struct s2n_client_hello_parsed_extension));
        struct s2n_client_hello_parsed_extension *parsed_named_group_extension = s2n_array_pushback(parsed_extensions);
        parsed_named_group_extension->extension_type = TLS_EXTENSION_SIGNATURE_ALGORITHMS;
        parsed_named_group_extension->extension = signature_algorithms_extension.blob;

        /* If only unknown algorithms are offered, expect choosing a scheme to fail */
        EXPECT_SUCCESS(s2n_client_extensions_recv(conn, parsed_extensions));
        EXPECT_EQUAL(conn->handshake_params.client_sig_hash_algs.len, sig_hash_algs.len);
        EXPECT_FAILURE(s2n_choose_sig_scheme_from_peer_preference_list(conn, &conn->handshake_params.client_sig_hash_algs,
                                &conn->secure.conn_sig_scheme));

        EXPECT_SUCCESS(s2n_stuffer_free(&signature_algorithms_extension));
        EXPECT_SUCCESS(s2n_array_free(parsed_extensions));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    {
        /* Test that a valid algorithm is chosen when it is offered among unknown algorithms */
        struct s2n_sig_scheme_list sig_hash_algs = {
            .iana_list = { 0xFF01, 0xFFFF, TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA384 },
            .len = 3,
        };
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer signature_algorithms_extension;
        EXPECT_SUCCESS(s2n_stuffer_alloc(&signature_algorithms_extension, 2 + (sig_hash_algs.len * 2)));
        GUARD(s2n_stuffer_write_uint16(&signature_algorithms_extension, sig_hash_algs.len * 2));
        for (int i = 0; i < sig_hash_algs.len; i++) {
                GUARD(s2n_stuffer_write_uint16(&signature_algorithms_extension, sig_hash_algs.iana_list[i]));
        }

        struct s2n_array *parsed_extensions = s2n_array_new(sizeof(struct s2n_client_hello_parsed_extension));
        struct s2n_client_hello_parsed_extension *parsed_named_group_extension = s2n_array_pushback(parsed_extensions);
        parsed_named_group_extension->extension_type = TLS_EXTENSION_SIGNATURE_ALGORITHMS;
        parsed_named_group_extension->extension = signature_algorithms_extension.blob;

        /* If a valid algorithm is offered among unknown algorithms, the valid one should be chosen */
        EXPECT_SUCCESS(s2n_client_extensions_recv(conn, parsed_extensions));
        EXPECT_EQUAL(conn->handshake_params.client_sig_hash_algs.len, sig_hash_algs.len);
        EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &conn->handshake_params.client_sig_hash_algs,
                                &conn->secure.conn_sig_scheme));
        EXPECT_EQUAL(conn->secure.conn_sig_scheme.iana_value, TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA384);

        EXPECT_SUCCESS(s2n_stuffer_free(&signature_algorithms_extension));
        EXPECT_SUCCESS(s2n_array_free(parsed_extensions));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
    return 0;
}
