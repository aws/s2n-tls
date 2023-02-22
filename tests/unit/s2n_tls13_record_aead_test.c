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

#include <stdio.h>
#include <string.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_record.h"
#include "tls/s2n_record_read.h"
#include "utils/s2n_safety.h"

const char protected_record_hex[] = "d1ff334a56f5bf"
                                    "f6594a07cc87b580233f500f45e489e7f33af35edf"
                                    "7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945"
                                    "cb960b4068905123ea78b111b429ba9191cd05d2a3"
                                    "89280f526134aadc7fc78c4b729df828b5ecf7b13b"
                                    "d9aefb0e57f271585b8ea9bb355c7c79020716cfb9"
                                    "b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf"
                                    "51427325250c7d0e509289444c9b3a648f1d71035d"
                                    "2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255"
                                    "cc744110c453baa4fcd610928d809810e4b7ed1a8f"
                                    "d991f06aa6248204797e36a6a73b70a2559c09ead6"
                                    "86945ba246ab66e5edd8044b4c6de3fcf2a89441ac"
                                    "66272fd8fb330ef8190579b3684596c960bd596eea"
                                    "520a56a8d650f563aad27409960dca63d3e688611e"
                                    "a5e22f4415cf9538d51a200c27034272968a264ed6"
                                    "540c84838d89f72c24461aad6d26f59ecaba9acbbb"
                                    "317b66d902f4f292a36ac1b639c637ce343117b659"
                                    "622245317b49eeda0c6258f100d7d961ffb138647e"
                                    "92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af"
                                    "36879018e3f252107f243d243dc7339d5684c8b037"
                                    "8bf30244da8c87c843f5e56eb4c5e8280a2b48052c"
                                    "f93b16499a66db7cca71e4599426f7d461e66f9988"
                                    "2bd89fc50800becca62d6c74116dbd2972fda1fa80"
                                    "f85df881edbe5a37668936b335583b599186dc5c69"
                                    "18a396fa48a181d6b6fa4f9d62d513afbb992f2b99"
                                    "2f67f8afe67f76913fa388cb5630c8ca01e0c65d11"
                                    "c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f551"
                                    "5614636c0b9b68c19ed2e31c0b3b66763038ebba42"
                                    "f3b38edc0399f3a9f23faa63978c317fc9fa66a73f"
                                    "60f0504de93b5b845e275592c12335ee340bbc4fdd"
                                    "d502784016e4b3be7ef04dda49f4b440a30cb5d2af"
                                    "939828fd4ae3794e44f94df5a631ede42c1719bfda"
                                    "bf0253fe5175be898e750edc53370d2b"; /* includes tag */

const char plaintext_record_hex[] =
        "080000240022000a00140012001d"
        "00170018001901000101010201030104001c000240"
        "01000000000b0001b9000001b50001b0308201ac30"
        "820115a003020102020102300d06092a864886f70d"
        "01010b0500300e310c300a06035504031303727361"
        "301e170d3136303733303031323335395a170d3236"
        "303733303031323335395a300e310c300a06035504"
        "03130372736130819f300d06092a864886f70d0101"
        "01050003818d0030818902818100b4bb498f827930"
        "3d980836399b36c6988c0c68de55e1bdb826d3901a"
        "2461eafd2de49a91d015abbc9a95137ace6c1af19e"
        "aa6af98c7ced43120998e187a80ee0ccb0524b1b01"
        "8c3e0b63264d449a6d38e22a5fda43084674803053"
        "0ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab"
        "9a8002c47428a6d35a8d88d79f7f1e3f0203010001"
        "a31a301830090603551d1304023000300b0603551d"
        "0f0404030205a0300d06092a864886f70d01010b05"
        "000381810085aad2a0e5b9276b908c65f73a726717"
        "0618a54c5f8a7b337d2df7a594365417f2eae8f8a5"
        "8c8f8172f9319cf36b7fd6c55b80f21a0301515672"
        "6096fd335e5e67f2dbf102702e608ccae6bec1fc63"
        "a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84"
        "e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229"
        "ac9187b42b4de100000f000084080400805a747c5d"
        "88fa9bd2e55ab085a61015b7211f824cd484145ab3"
        "ff52f1fda8477b0b7abc90db78e2d33a5c141a0786"
        "53fa6bef780c5ea248eeaaa785c4f394cab6d30bbe"
        "8d4859ee511f602957b15411ac027671459e46445c"
        "9ea58c181e818e95b8c3fb0bf3278409d3be152a3d"
        "a5043e063dda65cdf5aea20d53dfacd42f74f31400"
        "00209b9b141d906337fbd2cbdce71df4deda4ab42c"
        "309572cb7fffee5454b78f071816"; /* includes last byte for content type */

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Test s2n_tls13_aead_aad_init() */
    {
        s2n_stack_blob(aad, S2N_TLS13_AAD_LEN, S2N_TLS13_AAD_LEN);
        EXPECT_OK(s2n_tls13_aead_aad_init(662, 12, &aad));
        S2N_BLOB_FROM_HEX(expected_aad, "17030302a2");
        S2N_BLOB_EXPECT_EQUAL(expected_aad, aad);

        /* record length 16640 should be valid */
        EXPECT_SUCCESS(s2n_blob_zero(&aad));
        EXPECT_OK(s2n_tls13_aead_aad_init(16628, 12, &aad));

        /* record length 16641 should be invalid */
        EXPECT_SUCCESS(s2n_blob_zero(&aad));
        EXPECT_ERROR_WITH_ERRNO(s2n_tls13_aead_aad_init(16629, 12, &aad), S2N_ERR_RECORD_LIMIT);

        /* Test failure case: No AAD should be invalid */
        EXPECT_SUCCESS(s2n_blob_zero(&aad));
        EXPECT_ERROR(s2n_tls13_aead_aad_init(16629, 12, NULL));

        /* Test failure case: 0-length tag should be invalid */
        EXPECT_SUCCESS(s2n_blob_zero(&aad));
        EXPECT_ERROR(s2n_tls13_aead_aad_init(16628, 0, &aad));

        /* Test failure case: invalid record length (-1) should be invalid */
        EXPECT_ERROR(s2n_tls13_aead_aad_init(-1, 0, &aad));
    }

    /* Test s2n_tls13_aes_128_gcm_sha256 cipher suite with TLS 1.3 test vectors */
    {
        struct s2n_connection *conn;
        struct s2n_session_key session_key = { 0 };
        EXPECT_SUCCESS(s2n_session_key_alloc(&session_key));

        struct s2n_cipher_suite *cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS13;

        /* init record algorithm */
        EXPECT_SUCCESS(cipher_suite->record_alg->cipher->init(&session_key));
        S2N_BLOB_FROM_HEX(key, "3fce516009c21727d0f2e4e86ee403bc");
        EXPECT_SUCCESS(cipher_suite->record_alg->cipher->set_decryption_key(&session_key, &key));

        /* write protected record to conn in for testing */
        S2N_BLOB_FROM_HEX(protected_record, protected_record_hex);
        EXPECT_SUCCESS(s2n_stuffer_write(&conn->in, &protected_record));

        S2N_BLOB_FROM_HEX(iv, "5d313eb2671276ee13000b30");

        /* Test parsing of tls 1.3 aead record */
        EXPECT_SUCCESS(s2n_record_parse_aead(
                cipher_suite,
                conn,
                0, /* content_type doesn't matter for TLS 1.3 */
                protected_record.size,
                iv.data, /* implicit_iv */
                NULL,    /* mac not used for TLS 1.3 */
                conn->secure->client_sequence_number,
                &session_key));

        S2N_BLOB_FROM_HEX(plaintext_record, plaintext_record_hex);

        /* Because the decrypted payload contains both plaintext and tag,
         * we copy the contents for verification.
         */
        s2n_stack_blob(decrypted, plaintext_record.size, 1000);
        struct s2n_stuffer decrypted_stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_init(&decrypted_stuffer, &decrypted));

        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&decrypted_stuffer, conn->in.blob.data, plaintext_record.size));
        S2N_BLOB_EXPECT_EQUAL(plaintext_record, decrypted_stuffer.blob);

#define RESET_TEST                                                   \
    /* wipe conn in stuffer and refill protected record */           \
    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));                     \
    EXPECT_SUCCESS(s2n_stuffer_write(&conn->in, &protected_record)); \
    /* reset sequence number */                                      \
    conn->secure->client_sequence_number[7] = 0;

        /* Repeat the test to prove RESET_TEST works */
        RESET_TEST
        EXPECT_SUCCESS(s2n_record_parse_aead(cipher_suite, conn, 0, protected_record.size,
                iv.data, NULL, conn->secure->client_sequence_number, &session_key));

        /* Test record parsing failure from aead tag change */
        RESET_TEST
        conn->in.blob.data[protected_record.size - 2]++;
        EXPECT_FAILURE(s2n_record_parse_aead(cipher_suite, conn, 0, protected_record.size,
                iv.data, NULL, conn->secure->client_sequence_number, &session_key));

        /* Test incorrect ciphertext changes fails parsing */
        RESET_TEST
        conn->in.blob.data[0]++;
        EXPECT_FAILURE(s2n_record_parse_aead(cipher_suite, conn, 0, protected_record.size,
                iv.data, NULL, conn->secure->client_sequence_number, &session_key));

        /* Test wrong sequence number fails parsing */
        RESET_TEST
        conn->secure->client_sequence_number[7] = 1;
        EXPECT_FAILURE(s2n_record_parse_aead(cipher_suite, conn, 0, protected_record.size,
                iv.data, NULL, conn->secure->client_sequence_number, &session_key));

        /* Test IV changes fails parsing */
        RESET_TEST
        iv.data[0]++;
        EXPECT_FAILURE(s2n_record_parse_aead(cipher_suite, conn, 0, protected_record.size,
                iv.data, NULL, conn->secure->client_sequence_number, &session_key));

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_session_key_free(&session_key));
    };

    /* Test s2n_tls13_aes_128_gcm_sha256 cipher suite ENCRYPTION with TLS 1.3 test vectors */
    {
        struct s2n_connection *conn;
        struct s2n_cipher_suite *cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS13;

        conn->server->cipher_suite = cipher_suite;
        struct s2n_session_key *session_key = &conn->server->server_key;

        uint8_t *implicit_iv = conn->server->server_implicit_iv;

        /* init record algorithm */
        EXPECT_SUCCESS(cipher_suite->record_alg->cipher->init(session_key));
        S2N_BLOB_FROM_HEX(key, "3fce516009c21727d0f2e4e86ee403bc");
        EXPECT_SUCCESS(cipher_suite->record_alg->cipher->set_encryption_key(session_key, &key));

        S2N_BLOB_FROM_HEX(protected_record, protected_record_hex);

        S2N_BLOB_FROM_HEX(iv, "5d313eb2671276ee13000b30");

        /* copy iv bytes from input data */
        for (size_t i = 0; i < iv.size; i++) {
            implicit_iv[i] = iv.data[i];
        }

        /* Test parsing of tls 1.3 aead record */
        S2N_BLOB_FROM_HEX(plaintext_record, plaintext_record_hex);

        /* Make plaintext blob slice */
        struct s2n_blob in = {
            .data = &plaintext_record.data[0],
            .size = plaintext_record.size - 1, /* 1 byte less to remove content type */
        };

        /* Takes an input blob and writes to out stuffer then encrypt the payload */
        EXPECT_OK(s2n_record_write(conn, TLS_HANDSHAKE, &in));

        /* Verify opaque content type in tls 1.3 */
        EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
        /* Verify TLS legacy record version */
        EXPECT_EQUAL(conn->out.blob.data[1], 3);
        EXPECT_EQUAL(conn->out.blob.data[2], 3);
        /* Verify payload length */
        EXPECT_EQUAL((conn->out.blob.data[3] << 8) + conn->out.blob.data[4], protected_record.size);

        /* Make a slice of output bytes to verify */
        struct s2n_blob out = {
            .data = &conn->out.blob.data[S2N_TLS13_AAD_LEN],
            .size = protected_record.size
        };

        S2N_BLOB_EXPECT_EQUAL(out, protected_record);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test encrypt-decrypt roundtrip */
    {
        struct s2n_connection *conn;
        struct s2n_cipher_suite *cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS13;

        conn->server->cipher_suite = cipher_suite;
        struct s2n_session_key *session_key = &conn->server->server_key;

        uint8_t *implicit_iv = conn->server->server_implicit_iv;

        /* init record algorithm */
        EXPECT_SUCCESS(cipher_suite->record_alg->cipher->init(session_key));
        S2N_BLOB_FROM_HEX(key, "3fce516009c21727d0f2e4e86ee403bc");
        EXPECT_SUCCESS(cipher_suite->record_alg->cipher->set_encryption_key(session_key, &key));
        EXPECT_SUCCESS(cipher_suite->record_alg->cipher->set_decryption_key(session_key, &key));

        S2N_BLOB_FROM_HEX(iv, "5d313eb2671276ee13000b30");

        /* copy iv bytes from input data */
        for (size_t i = 0; i < iv.size; i++) {
            implicit_iv[i] = iv.data[i];
        }

        /* Test parsing of tls 1.3 aead record */
        S2N_BLOB_LABEL(expect_plaintext, "Hello world");

        static uint8_t hello_data[] = "Hello world";
        struct s2n_blob plaintext = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&plaintext, hello_data, sizeof(hello_data) - 1));

        /* Takes an input blob and writes to out stuffer then encrypt the payload */
        EXPECT_OK(s2n_record_write(conn, TLS_HANDSHAKE, &plaintext));

        /* Reset sequence number */
        conn->secure->client_sequence_number[7] = 0;

        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, &conn->out.blob.data[S2N_TLS13_AAD_LEN], plaintext.size + 16 + 1)); /* tag length + content type */

        /* Make a slice of output bytes to verify */
        struct s2n_blob encrypted = {
            .data = &conn->in.blob.data[0],
            .size = plaintext.size + 16 + 1
        };

        /* Decrypt payload */
        EXPECT_SUCCESS(s2n_record_parse_aead(
                cipher_suite,
                conn,
                0, /* content_type */
                encrypted.size,
                iv.data, /* implicit_iv */
                NULL,    /* mac not used for TLS 1.3 */
                conn->secure->client_sequence_number,
                session_key));

        struct s2n_blob decrypted = {
            .data = &conn->in.blob.data[0],
            .size = expect_plaintext.size
        };

        /* Verify decrypted payload */
        S2N_BLOB_EXPECT_EQUAL(decrypted, expect_plaintext);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test that CCS in TLS 1.3 modes should be sent without encryption */
    {
        s2n_mode modes[] = { S2N_SERVER, S2N_CLIENT };
        for (size_t m = 0; m < s2n_array_len(modes); m++) {
            struct s2n_connection *conn;
            struct s2n_cipher_suite *cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            EXPECT_NOT_NULL(conn = s2n_connection_new(modes[m]));
            conn->actual_protocol_version = S2N_TLS13;
            conn->server_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = cipher_suite;
            conn->server = conn->secure;
            conn->client = conn->secure;

            /* init record algorithm */
            EXPECT_SUCCESS(cipher_suite->record_alg->cipher->init(&conn->secure->server_key));
            EXPECT_SUCCESS(cipher_suite->record_alg->cipher->init(&conn->secure->client_key));
            S2N_BLOB_FROM_HEX(key, "3fce516009c21727d0f2e4e86ee403bc");
            EXPECT_SUCCESS(cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure->server_key, &key));
            EXPECT_SUCCESS(cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure->client_key, &key));

            S2N_BLOB_FROM_HEX(protected_record, protected_record_hex);
            S2N_BLOB_FROM_HEX(iv, "5d313eb2671276ee13000b30");

            /* copy iv bytes from input data */
            for (size_t i = 0; i < iv.size; i++) {
                conn->secure->server_implicit_iv[i] = iv.data[i];
                conn->secure->client_implicit_iv[i] = iv.data[i];
            }

            /* Test parsing of tls 1.3 aead record */
            S2N_BLOB_FROM_HEX(plaintext_record, plaintext_record_hex);

            uint8_t change_cipher_spec[] = { 1 };
            struct s2n_blob in = { .data = change_cipher_spec, .size = sizeof(change_cipher_spec) };

            /* Takes an input blob and writes to out stuffer then encrypt the payload */
            EXPECT_OK(s2n_record_write(conn, TLS_CHANGE_CIPHER_SPEC, &in));

            S2N_STUFFER_READ_EXPECT_EQUAL(&conn->out, TLS_CHANGE_CIPHER_SPEC, uint8);
            S2N_STUFFER_READ_EXPECT_EQUAL(&conn->out, 0x0303, uint16);
            S2N_STUFFER_READ_EXPECT_EQUAL(&conn->out, 1, uint16);
            S2N_STUFFER_READ_EXPECT_EQUAL(&conn->out, 1, uint8);

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));

            /* An encrypted TLS 1.3 HANDSHAKE type will look like a APPLICATION_DATA over the wire */
            EXPECT_OK(s2n_record_write(conn, TLS_HANDSHAKE, &in));

            /* now test that application data writes encrypted payload */
            S2N_STUFFER_READ_EXPECT_EQUAL(&conn->out, TLS_APPLICATION_DATA, uint8);
            S2N_STUFFER_READ_EXPECT_EQUAL(&conn->out, 0x0303, uint16);
            S2N_STUFFER_READ_EXPECT_EQUAL(&conn->out, 18, uint16);
            S2N_STUFFER_READ_EXPECT_EQUAL(&conn->out, 216, uint8);

            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->header_in, TLS_CHANGE_CIPHER_SPEC));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&conn->header_in, 0x0303));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&conn->header_in, 1));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, 1));

            /* Parses unencrypted CCS record correctly */
            EXPECT_SUCCESS(s2n_record_parse(conn));

            /* now if this was an application data, it cannot be parsed */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->header_in, TLS_APPLICATION_DATA));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&conn->header_in, 0x0303));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&conn->header_in, 1));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, 1));
            EXPECT_FAILURE(s2n_record_parse(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    };

    END_TEST();
}
