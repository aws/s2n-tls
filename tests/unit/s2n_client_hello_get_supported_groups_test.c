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

#include "pq-crypto/s2n_pq.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_client_supported_groups.h"
#include "tls/s2n_client_hello.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_random.h"

#define S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT 16

/* Each supported group is 2 bytes. */
#define S2N_TEST_SUPPORTED_GROUPS_LIST_SIZE (S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT * S2N_SUPPORTED_GROUP_SIZE)

/* 2 length bytes + space for the list of supported groups. */
#define S2N_TEST_SUPPORTED_GROUPS_EXTENSION_SIZE (2 + S2N_TEST_SUPPORTED_GROUPS_LIST_SIZE)

struct s2n_client_hello_context {
    struct s2n_stuffer *sent_supported_groups_extension;
    int invoked_count;
};

int s2n_check_received_supported_groups_cb(struct s2n_connection *conn, void *ctx)
{
    EXPECT_NOT_NULL(ctx);

    struct s2n_client_hello_context *context = (struct s2n_client_hello_context *) ctx;
    EXPECT_NOT_NULL(context->sent_supported_groups_extension);
    context->invoked_count += 1;

    struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(conn);
    EXPECT_NOT_NULL(client_hello);

    uint16_t received_groups[S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT] = { 0 };
    uint16_t received_groups_count = 0;
    EXPECT_SUCCESS(s2n_client_hello_get_supported_groups(client_hello, received_groups,
            s2n_array_len(received_groups), &received_groups_count));

    uint16_t sent_groups_count = 0;
    EXPECT_OK(s2n_supported_groups_parse_count(context->sent_supported_groups_extension, &sent_groups_count));
    EXPECT_EQUAL(received_groups_count, sent_groups_count);

    for (size_t i = 0; i < received_groups_count; i++) {
        uint16_t received_group = received_groups[i];

        /* s2n_stuffer_read_uint16 is used to read each of the sent supported groups in
         * network-order endianness, and compare them to the received supported groups which have
         * already been converted to the machine's endianness.
         */
        uint16_t sent_group = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(context->sent_supported_groups_extension, &sent_group));

        EXPECT_EQUAL(received_group, sent_group);
    }

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    s2n_extension_type_id supported_groups_id = 0;
    EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(S2N_EXTENSION_SUPPORTED_GROUPS, &supported_groups_id));

    /* Safety */
    {
        struct s2n_client_hello client_hello = { 0 };
        uint16_t supported_groups[S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT] = { 0 };
        uint16_t supported_groups_count = 0;

        int ret = s2n_client_hello_get_supported_groups(NULL, supported_groups, s2n_array_len(supported_groups),
                &supported_groups_count);
        EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_NULL);
        EXPECT_EQUAL(supported_groups_count, 0);

        ret = s2n_client_hello_get_supported_groups(&client_hello, NULL, s2n_array_len(supported_groups),
                &supported_groups_count);
        EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_NULL);
        EXPECT_EQUAL(supported_groups_count, 0);

        ret = s2n_client_hello_get_supported_groups(&client_hello, supported_groups, s2n_array_len(supported_groups), NULL);
        EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_NULL);
        EXPECT_EQUAL(supported_groups_count, 0);
    }

    /* Ensure that the maximum size of the provided supported groups list is respected. */
    {
        struct s2n_client_hello client_hello = { 0 };

        uint8_t extension_data[S2N_TEST_SUPPORTED_GROUPS_EXTENSION_SIZE] = { 0 };
        struct s2n_blob extension_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&extension_blob, extension_data, sizeof(extension_data)));

        s2n_parsed_extension *supported_groups_extension = &client_hello.extensions.parsed_extensions[supported_groups_id];
        supported_groups_extension->extension_type = S2N_EXTENSION_SUPPORTED_GROUPS;
        supported_groups_extension->extension = extension_blob;

        struct s2n_stuffer extension_stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_init(&extension_stuffer, &extension_blob));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension_stuffer, S2N_TEST_SUPPORTED_GROUPS_LIST_SIZE));

        uint16_t supported_groups[S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT] = { 0 };
        uint16_t supported_groups_count = 0;

        /* Fail if the provided buffer is too small. */
        int ret = s2n_client_hello_get_supported_groups(&client_hello, supported_groups,
                S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT - 1, &supported_groups_count);
        EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_INSUFFICIENT_MEM_SIZE);
        EXPECT_EQUAL(supported_groups_count, 0);

        EXPECT_SUCCESS(s2n_stuffer_reread(&extension_stuffer));

        /* Succeed with a correctly sized buffer. */
        EXPECT_SUCCESS(s2n_client_hello_get_supported_groups(&client_hello, supported_groups,
                S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT, &supported_groups_count));
        EXPECT_EQUAL(supported_groups_count, S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT);
    }

    /* Error if the client hello isn't parsed yet. */
    {
        struct s2n_client_hello client_hello = { 0 };

        uint16_t supported_groups[S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT] = { 0 };
        uint16_t supported_groups_count = 0;
        int ret = s2n_client_hello_get_supported_groups(&client_hello, supported_groups,
                s2n_array_len(supported_groups), &supported_groups_count);
        EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_EXTENSION_NOT_RECEIVED);
    }

    /* Error if a supported groups extension wasn't received. */
    for (int disable_ecc = 0; disable_ecc <= 1; disable_ecc++) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        if (disable_ecc) {
            /* The 20150202 security policy doesn't contain any ECDHE cipher suites, so the
             * supported groups extension won't be sent.
             */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20150202"));
        } else {
            /* The 20170210 security policy contains ECDHE cipher suites, so the supported groups
             * extension will be sent.
             */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20170210"));
        }

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        EXPECT_SUCCESS(s2n_client_hello_send(client));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client->handshake.io, &server->handshake.io,
                s2n_stuffer_data_available(&client->handshake.io)));
        EXPECT_SUCCESS(s2n_client_hello_recv(server));

        struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(server);
        EXPECT_NOT_NULL(client_hello);

        bool supported_groups_extension_exists = false;
        EXPECT_SUCCESS(s2n_client_hello_has_extension(client_hello, S2N_EXTENSION_SUPPORTED_GROUPS,
                &supported_groups_extension_exists));
        EXPECT_EQUAL(supported_groups_extension_exists, !disable_ecc);

        uint16_t supported_groups[S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT] = { 0 };
        uint16_t supported_groups_count = 0;
        int ret = s2n_client_hello_get_supported_groups(client_hello, supported_groups, s2n_array_len(supported_groups),
                &supported_groups_count);

        if (disable_ecc) {
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_EXTENSION_NOT_RECEIVED);
            EXPECT_EQUAL(supported_groups_count, 0);
        } else {
            EXPECT_SUCCESS(ret);

            /* The 20170210 security policy contains 2 ECC curves. */
            EXPECT_EQUAL(supported_groups_count, 2);
        }
    }

    /* Test parsing a supported groups extension with a malformed groups list length. */
    {
        struct s2n_client_hello client_hello = { 0 };

        s2n_parsed_extension *supported_groups_extension = &client_hello.extensions.parsed_extensions[supported_groups_id];
        supported_groups_extension->extension_type = S2N_EXTENSION_SUPPORTED_GROUPS;

        /* Test parsing a correct groups list length */
        {
            uint8_t extension_data[S2N_TEST_SUPPORTED_GROUPS_EXTENSION_SIZE] = { 0 };
            struct s2n_blob extension_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&extension_blob, extension_data, sizeof(extension_data)));
            supported_groups_extension->extension = extension_blob;

            struct s2n_stuffer extension_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&extension_stuffer, &extension_blob));

            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension_stuffer, S2N_TEST_SUPPORTED_GROUPS_LIST_SIZE));

            uint16_t supported_groups[S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT] = { 0 };
            uint16_t supported_groups_count = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_supported_groups(&client_hello, supported_groups,
                    s2n_array_len(supported_groups), &supported_groups_count));

            EXPECT_EQUAL(supported_groups_count, S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT);
        }

        /* Test parsing a groups list length that is larger than the extension length */
        {
            uint8_t extension_data[S2N_TEST_SUPPORTED_GROUPS_EXTENSION_SIZE] = { 0 };
            struct s2n_blob extension_blob = { 0 };
            uint32_t extension_too_small_size = S2N_TEST_SUPPORTED_GROUPS_EXTENSION_SIZE - 2;
            EXPECT_SUCCESS(s2n_blob_init(&extension_blob, extension_data, extension_too_small_size));
            supported_groups_extension->extension = extension_blob;

            struct s2n_stuffer extension_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&extension_stuffer, &extension_blob));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension_stuffer, S2N_TEST_SUPPORTED_GROUPS_LIST_SIZE));

            uint16_t supported_groups[S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT] = { 0 };
            uint16_t supported_groups_count = 0;
            int ret = s2n_client_hello_get_supported_groups(&client_hello, supported_groups,
                    s2n_array_len(supported_groups), &supported_groups_count);
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_INVALID_PARSED_EXTENSIONS);

            EXPECT_EQUAL(supported_groups_count, 0);
        }

        /* Test parsing a groups list that contains a malformed supported group */
        {
            uint8_t extension_data[S2N_TEST_SUPPORTED_GROUPS_EXTENSION_SIZE] = { 0 };
            struct s2n_blob extension_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&extension_blob, extension_data, sizeof(extension_data)));
            supported_groups_extension->extension = extension_blob;

            struct s2n_stuffer extension_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&extension_stuffer, &extension_blob));

            uint16_t one_and_a_half_groups_size = 3;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension_stuffer, one_and_a_half_groups_size));

            uint16_t supported_groups[S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT] = { 0 };
            uint16_t supported_groups_count = 0;
            int ret = s2n_client_hello_get_supported_groups(&client_hello, supported_groups,
                    s2n_array_len(supported_groups), &supported_groups_count);
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_INVALID_PARSED_EXTENSIONS);

            EXPECT_EQUAL(supported_groups_count, 0);
        }
    }

    /* Ensure that the supported groups in the client hello are written to the output array. */
    {
        struct s2n_client_hello client_hello = { 0 };

        s2n_parsed_extension *supported_groups_extension = &client_hello.extensions.parsed_extensions[supported_groups_id];
        supported_groups_extension->extension_type = S2N_EXTENSION_SUPPORTED_GROUPS;

        for (uint16_t test_groups_count = 0; test_groups_count < S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT; test_groups_count++) {
            uint16_t test_groups_list_size = test_groups_count * 2;

            uint8_t test_groups_list_data[S2N_TEST_SUPPORTED_GROUPS_LIST_SIZE] = { 0 };
            struct s2n_blob test_groups_list_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&test_groups_list_blob, test_groups_list_data, test_groups_list_size));
            EXPECT_OK(s2n_get_public_random_data(&test_groups_list_blob));

            uint8_t extension_data[S2N_TEST_SUPPORTED_GROUPS_EXTENSION_SIZE] = { 0 };
            struct s2n_blob extension_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&extension_blob, extension_data, sizeof(extension_data)));
            supported_groups_extension->extension = extension_blob;

            struct s2n_stuffer extension_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&extension_stuffer, &extension_blob));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&extension_stuffer, test_groups_list_size));
            EXPECT_SUCCESS(s2n_stuffer_write(&extension_stuffer, &test_groups_list_blob));

            uint16_t supported_groups[S2N_TEST_SUPPORTED_GROUPS_LIST_COUNT] = { 0 };
            uint16_t supported_groups_count = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_supported_groups(&client_hello, supported_groups,
                    s2n_array_len(supported_groups), &supported_groups_count));
            EXPECT_EQUAL(supported_groups_count, test_groups_count);

            struct s2n_stuffer test_groups_list_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init_written(&test_groups_list_stuffer, &test_groups_list_blob));

            for (size_t i = 0; i < supported_groups_count; i++) {
                uint16_t test_group = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&test_groups_list_stuffer, &test_group));
                uint16_t written_group = supported_groups[i];

                EXPECT_EQUAL(test_group, written_group);
            }
        }
    }

    /* Self-talk: Ensure that the retrieved supported groups match what was sent by the client.
     *
     * This test also ensures that s2n_client_hello_get_supported_groups is usable from within the
     * client hello callback.
     */
    {
        /* Test security policies with a range of different ECC curves and KEM groups. */
        const char *policies[] = {
            "20170210",
            "20190801",
            "AWS-CRT-SDK-TLSv1.2-2023",
            "20230317",
            "20210816",
            "PQ-TLS-1-0-2021-05-20",
            "PQ-TLS-1-2-2023-04-08",
            "test_all"
        };

        for (int version_index = 0; version_index < s2n_array_len(policies); version_index++) {
            const char *policy = policies[version_index];

            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(client_config);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, policy));

            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(server_config);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(server_config));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, policy));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

            struct s2n_client_hello_context context = {
                .invoked_count = 0,
            };
            EXPECT_SUCCESS(s2n_config_set_client_hello_cb(server_config, s2n_check_received_supported_groups_cb,
                    &context));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

            uint8_t sent_supported_groups_data[S2N_TEST_SUPPORTED_GROUPS_EXTENSION_SIZE];
            struct s2n_blob sent_supported_groups_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&sent_supported_groups_blob, sent_supported_groups_data,
                    s2n_array_len(sent_supported_groups_data)));

            struct s2n_stuffer sent_supported_groups_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&sent_supported_groups_stuffer, &sent_supported_groups_blob));
            EXPECT_SUCCESS(s2n_client_supported_groups_extension.send(client_conn, &sent_supported_groups_stuffer));
            context.sent_supported_groups_extension = &sent_supported_groups_stuffer;

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_EQUAL(context.invoked_count, 1);
        }
    }

    END_TEST();
}
