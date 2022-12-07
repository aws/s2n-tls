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

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_result.h"

/* Get access to s2n_handshake_read_io */
#include "tls/s2n_handshake_io.c"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    uint8_t bad_record[] = {
        0x17,       /* ContentType opaque_type = application_data */
        0x03, 0x03, /* ProtocolVersion legacy_record_version = 0x0303 */
        0x00, 0x10, /* uint16 length */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* opaque encrypted_record[TLSCiphertext.length] */
    };

    struct s2n_cipher_suite *test_cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
    uint8_t test_key_bytes[S2N_TLS13_SECRET_MAX_LEN] = "gibberish key";
    struct s2n_blob test_key = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&test_key, test_key_bytes,
            test_cipher_suite->record_alg->cipher->key_material_size));

    /**
     *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
     *= type=test
     *# If the client attempts a 0-RTT handshake but the server
     *# rejects it, the server will generally not have the 0-RTT record
     *# protection keys and must instead use trial decryption (either with
     *# the 1-RTT handshake keys or by looking for a cleartext ClientHello in
     *# the case of a HelloRetryRequest) to find the first non-0-RTT message.
     *#
     *# If the server chooses to accept the "early_data" extension, then it
     *# MUST comply with the same error-handling requirements specified for
     *# all records when processing early data records.  Specifically, if the
     *# server fails to decrypt a 0-RTT record following an accepted
     *# "early_data" extension, it MUST terminate the connection with a
     *# "bad_record_mac" alert as per Section 5.2.
     */
    {
        /* Server */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

            server_conn->secure->cipher_suite = test_cipher_suite;
            POSIX_GUARD(server_conn->secure->cipher_suite->record_alg->cipher->init(&server_conn->secure->client_key));
            POSIX_GUARD(server_conn->secure->cipher_suite->record_alg->cipher->set_decryption_key(&server_conn->secure->client_key, &test_key));
            server_conn->client = server_conn->secure;

            DEFER_CLEANUP(struct s2n_stuffer io_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&io_stuffer, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&io_stuffer, &io_stuffer, server_conn));

            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&io_stuffer, bad_record, sizeof(bad_record)));

            /* Fail for bad record if early data was not requested */
            {
                EXPECT_SUCCESS(s2n_stuffer_reread(&io_stuffer));
                server_conn->early_data_state = S2N_EARLY_DATA_NOT_REQUESTED;
                EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_read_io(server_conn), S2N_ERR_DECRYPT);
            };

            /* Fail for bad record if early data was accepted */
            {
                EXPECT_SUCCESS(s2n_stuffer_reread(&io_stuffer));
                server_conn->early_data_state = S2N_EARLY_DATA_ACCEPTED;
                EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_read_io(server_conn), S2N_ERR_DECRYPT);
            };

            /* Succeed for bad record if early data was rejected */
            {
                EXPECT_SUCCESS(s2n_stuffer_reread(&io_stuffer));
                server_conn->early_data_state = S2N_EARLY_DATA_REJECTED;
                EXPECT_SUCCESS(s2n_handshake_read_io(server_conn));
            };

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Client */
        {
            /* Fail for bad record if early data was rejected.
             * Clients send early data but do not receive it, so a bad record is still an error. */
            {
                struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

                client_conn->secure->cipher_suite = test_cipher_suite;
                POSIX_GUARD(client_conn->secure->cipher_suite->record_alg->cipher->init(&client_conn->secure->server_key));
                POSIX_GUARD(client_conn->secure->cipher_suite->record_alg->cipher->set_decryption_key(&client_conn->secure->server_key, &test_key));
                client_conn->server = client_conn->secure;

                DEFER_CLEANUP(struct s2n_stuffer io_stuffer = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&io_stuffer, S2N_DEFAULT_RECORD_LENGTH));
                EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&io_stuffer, &io_stuffer, client_conn));

                EXPECT_SUCCESS(s2n_stuffer_write_bytes(&io_stuffer, bad_record, sizeof(bad_record)));

                client_conn->early_data_state = S2N_EARLY_DATA_REJECTED;
                EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_read_io(client_conn), S2N_ERR_DECRYPT);

                EXPECT_SUCCESS(s2n_connection_free(client_conn));
            };
        };
    };

    END_TEST();
}
