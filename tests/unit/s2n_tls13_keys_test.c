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

#include <string.h>

#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hmac.h"
#include "crypto/s2n_hkdf.h"
#include "crypto/s2n_tls13_keys.h"

#include "tls/s2n_tls13_handshake.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    /* TLS 1.3 Test Vectors from https://tools.ietf.org/html/rfc8448 */

    S2N_BLOB_FROM_HEX(expected_early_secret,
        "33ad0a1c607ec03b09e6cd9893680ce2"
        "10adf300aa1f2660e1b22e10f170f92a");

    S2N_BLOB_FROM_HEX(expect_derived_handshake_secret,
        "6f2615a108c702c5678f54fc9dba"
        "b69716c076189c48250cebeac3576c3611ba");

    S2N_BLOB_FROM_HEX(client_hello,
        "010000c00303cb34ecb1e78163"
        "ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283"
        "024dece7000006130113031302010000910000000b"
        "0009000006736572766572ff01000100000a001400"
        "12001d001700180019010001010102010301040023"
        "0000003300260024001d002099381de560e4bd43d2"
        "3d8e435a7dbafeb3c06e51c13cae4d5413691e529a"
        "af2c002b0003020304000d0020001e040305030603"
        "020308040805080604010501060102010402050206"
        "020202002d00020101001c00024001");

    S2N_BLOB_FROM_HEX(server_hello,
        "020000560303a6af06a4121860"
        "dc5e6e60249cd34c95930c8ac5cb1434dac155772e"
        "d3e2692800130100002e00330024001d0020c98288"
        "76112095fe66762bdbf7c672e156d6cc253b833df1"
        "dd69b1b04e751f0f002b00020304");

    S2N_BLOB_FROM_HEX(encrypted_extensions,
        "080000240022000a001400"
        "12001d00170018001901000101010201030104001c"
        "0002400100000000");

    S2N_BLOB_FROM_HEX(certificate,
        "0b0001b9000001b50001b03082"
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
        "961229ac9187b42b4de10000");

    S2N_BLOB_FROM_HEX(certificate_verify,
        "0f000084080400805a747c"
        "5d88fa9bd2e55ab085a61015b7211f824cd484145a"
        "b3ff52f1fda8477b0b7abc90db78e2d33a5c141a07"
        "8653fa6bef780c5ea248eeaaa785c4f394cab6d30b"
        "be8d4859ee511f602957b15411ac027671459e4644"
        "5c9ea58c181e818e95b8c3fb0bf3278409d3be152a"
        "3da5043e063dda65cdf5aea20d53dfacd42f74f3");

    S2N_BLOB_FROM_HEX(server_finished,
        "140000209b9b141d906337fbd2cb"
        "dce71df4deda4ab42c309572cb7fffee5454b78f07"
        "18");

    S2N_BLOB_FROM_HEX(client_finished, 
        "14000020a8ec436d677634ae525ac"
        "1fcebe11a039ec17694fac6e98527b642f2edd5ce61");

    S2N_BLOB_FROM_HEX(expect_server_finished_verify,
        "9b9b141d906337fbd2cbdce71df4"
        "deda4ab42c309572cb7fffee5454b78f0718");

    S2N_BLOB_FROM_HEX(expect_client_finished_verify,
        "a8ec436d677634ae525ac1fcebe1"
        "1a039ec17694fac6e98527b642f2edd5ce61");

    S2N_BLOB_FROM_HEX(ecdhe,
        "8bd4054fb55b9d63fdfbacf9f04b9f0d"
        "35e6d63f537563efd46272900f89492d");

    S2N_BLOB_FROM_HEX(expect_derived_client_handshake_secret,
        "b3eddb126e067f35a780b3abf45e"
        "2d8f3b1a950738f52e9600746a0e27a55a21");

    S2N_BLOB_FROM_HEX(expect_derived_server_handshake_secret,
        "b67b7d690cc16c4e75e54213cb2d"
        "37b4e9c912bcded9105d42befd59d391ad38");

    S2N_BLOB_FROM_HEX(expect_derived_master_secret,
        "43de77e0c77713859a944db9db25"
        "90b53190a65b3ee2e4f12dd7a0bb7ce254b4");

    S2N_BLOB_FROM_HEX(expect_extract_master_secret,
        "18df06843d13a08bf2a449844c5f8a"
        "478001bc4d4c627984d5a41da8d0402919");

    S2N_BLOB_FROM_HEX(expect_derived_client_application_traffic_secret,
        "9e40646ce79a7f9dc05af8889bce"
        "6552875afa0b06df0087f792ebb7c17504a5");
    S2N_BLOB_FROM_HEX(expect_derived_server_application_traffic_secret,
        "a11af9f05531f856ad47116b45a9"
        "50328204b4f44bfb6b3a4b4f1f3fcb631643");

    S2N_BLOB_FROM_HEX(expect_derived_master_resumption_secret, 
        "7df235f2031d2a051287d02b0241"
        "b0bfdaf86cc856231f2d5aba46c434ec196c");
    
    S2N_BLOB_FROM_HEX(ticket_nonce, "0000");

    S2N_BLOB_FROM_HEX(expected_session_ticket_secret, 
        "4ecd0eb6ec3b4d87f5d6028f922c"
        "a4c5851a277fd41311c9e62d2c9492e1c4f3");

    S2N_BLOB_FROM_HEX(expect_handshake_traffic_server_key,
        "3fce516009c21727d0f2e4e86ee403bc");

    S2N_BLOB_FROM_HEX(expect_handshake_traffic_server_iv,
        "5d313eb2671276ee13000b30");

    S2N_BLOB_FROM_HEX(expect_derived_client_handshake_secret_digest,
        "860c06edc07858ee8e78f0e7428c58ed"
        "d6b43f2ca3e6e95f02ed063cf0e1cad8");

    /* KeyUpdate Vectors from Openssl s_client implementation of KeyUpdate. The ciphersuite
     * that produced this secret was s2n_tls13_aes_256_gcm_sha384.
     */

    S2N_BLOB_FROM_HEX(application_secret,
        "4bc28934ddd802b00f479e14a72d7725dab45d32b3b145f29"
        "e4c5b56677560eb5236b168c71c5c75aa52f3e20ee89bfb");

    S2N_BLOB_FROM_HEX(updated_application_secret,
        "ee85dd54781bd4d8a100589a9fe6ac9a3797b811e977f549cd"
        "531be2441d7c63e2b9729d145c11d84af35957727565a4");

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    DEFER_CLEANUP(struct s2n_tls13_keys secrets = {0}, s2n_tls13_keys_free);

    EXPECT_SUCCESS(s2n_tls13_keys_init(&secrets, S2N_HMAC_SHA256));

    /* Derive Early Secrets */
    EXPECT_SUCCESS(s2n_tls13_derive_early_secret(&secrets, NULL));

    S2N_BLOB_EXPECT_EQUAL(secrets.extract_secret, expected_early_secret);
    S2N_BLOB_EXPECT_EQUAL(secrets.derive_secret, expect_derived_handshake_secret);

    DEFER_CLEANUP(struct s2n_hash_state hash_state, s2n_hash_free);
    EXPECT_SUCCESS(s2n_hash_new(&hash_state));
    EXPECT_SUCCESS(s2n_hash_init(&hash_state, secrets.hash_algorithm));
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, client_hello.data, client_hello.size));
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, server_hello.data, server_hello.size));

    s2n_tls13_key_blob(client_handshake_secret, secrets.size);
    s2n_tls13_key_blob(server_handshake_secret, secrets.size);
    s2n_tls13_key_blob(message_digest, secrets.size);

    DEFER_CLEANUP(struct s2n_hash_state hash_state_copy, s2n_hash_free);
    EXPECT_SUCCESS(s2n_hash_new(&hash_state_copy));

    EXPECT_SUCCESS(s2n_hash_copy(&hash_state_copy, &hash_state));
    EXPECT_SUCCESS(s2n_hash_digest(&hash_state_copy, message_digest.data, message_digest.size));
    S2N_BLOB_EXPECT_EQUAL(expect_derived_client_handshake_secret_digest, message_digest);

    /* Derive Handshake Secrets */
    EXPECT_SUCCESS(s2n_tls13_extract_handshake_secret(&secrets, &ecdhe));
    EXPECT_SUCCESS(s2n_tls13_derive_handshake_traffic_secret(&secrets, &message_digest, &client_handshake_secret, S2N_CLIENT));
    EXPECT_SUCCESS(s2n_tls13_derive_handshake_traffic_secret(&secrets, &message_digest, &server_handshake_secret, S2N_SERVER));

    S2N_BLOB_EXPECT_EQUAL(expect_derived_client_handshake_secret, client_handshake_secret);
    S2N_BLOB_EXPECT_EQUAL(expect_derived_server_handshake_secret, server_handshake_secret);
    S2N_BLOB_EXPECT_EQUAL(expect_derived_master_secret, secrets.derive_secret);

    /* Derive Application Secrets */
    s2n_tls13_key_blob(client_application_secret, secrets.size);
    s2n_tls13_key_blob(server_application_secret, secrets.size);

    /* Update handshake transcript hashes */
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, encrypted_extensions.data, encrypted_extensions.size));
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, certificate.data, certificate.size));
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, certificate_verify.data, certificate_verify.size));

    /* Derive server finished key */
    s2n_stack_blob(server_finished_key, secrets.size, S2N_TLS13_SECRET_MAX_LEN);
    EXPECT_SUCCESS(s2n_tls13_derive_finished_key(&secrets, &server_handshake_secret, &server_finished_key));

    s2n_tls13_key_blob(server_finished_verify, secrets.size);
    EXPECT_SUCCESS(s2n_hash_copy(&hash_state_copy, &hash_state));
    EXPECT_SUCCESS(s2n_tls13_calculate_finished_mac(&secrets, &server_finished_key, &hash_state_copy, &server_finished_verify));

    S2N_BLOB_EXPECT_EQUAL(expect_server_finished_verify, server_finished_verify);

    /* Update handshake hashes with Server Finished */
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, server_finished.data, server_finished.size));

    s2n_stack_blob(client_finished_key, secrets.size, S2N_TLS13_SECRET_MAX_LEN);
    EXPECT_SUCCESS(s2n_tls13_derive_finished_key(&secrets, &client_handshake_secret, &client_finished_key));

    s2n_tls13_key_blob(client_finished_verify, secrets.size);
    EXPECT_SUCCESS(s2n_hash_copy(&hash_state_copy, &hash_state));
    EXPECT_SUCCESS(s2n_tls13_calculate_finished_mac(&secrets, &client_finished_key, &hash_state_copy, &client_finished_verify));

    /* Test Client Finished MAC hash */
    S2N_BLOB_EXPECT_EQUAL(expect_client_finished_verify, client_finished_verify);

    EXPECT_SUCCESS(s2n_tls13_extract_master_secret(&secrets));
    S2N_BLOB_EXPECT_EQUAL(expect_extract_master_secret, secrets.extract_secret);

    EXPECT_SUCCESS(s2n_hash_copy(&hash_state_copy, &hash_state));
    EXPECT_SUCCESS(s2n_hash_digest(&hash_state_copy, message_digest.data, message_digest.size));

    EXPECT_SUCCESS(s2n_tls13_derive_application_secret(&secrets, &message_digest, &client_application_secret, S2N_CLIENT));
    S2N_BLOB_EXPECT_EQUAL(expect_derived_client_application_traffic_secret, client_application_secret);

    EXPECT_SUCCESS(s2n_tls13_derive_application_secret(&secrets, &message_digest, &server_application_secret, S2N_SERVER));
    S2N_BLOB_EXPECT_EQUAL(expect_derived_server_application_traffic_secret, server_application_secret);

    /* Update handshake hashes with Client Finished */
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, client_finished.data, client_finished.size));
    
    /* Test session resumption secret */
    s2n_tls13_key_blob(master_resumption_secret, secrets.size);
    EXPECT_SUCCESS(s2n_tls13_derive_resumption_master_secret(&secrets, &hash_state, &master_resumption_secret));
    S2N_BLOB_EXPECT_EQUAL(expect_derived_master_resumption_secret, master_resumption_secret);

    /* Test individual session resumption ticket secret */
    s2n_tls13_key_blob(session_ticket_secret, secrets.size);
    EXPECT_OK(s2n_tls13_derive_session_ticket_secret(&secrets, &master_resumption_secret, &ticket_nonce, &session_ticket_secret));
    S2N_BLOB_EXPECT_EQUAL(expected_session_ticket_secret, session_ticket_secret);

    /* Test Traffic Keys */
    s2n_tls13_key_blob(handshake_traffic_client_key, 16);
    s2n_tls13_key_blob(handshake_traffic_client_iv, 12);

    s2n_tls13_key_blob(handshake_traffic_server_key, 16);
    s2n_tls13_key_blob(handshake_traffic_server_iv, 12);

    EXPECT_SUCCESS(s2n_tls13_derive_traffic_keys(&secrets,
        &server_handshake_secret,
        &handshake_traffic_server_key,
        &handshake_traffic_server_iv));

    EXPECT_SUCCESS(s2n_tls13_derive_traffic_keys(&secrets,
        &client_handshake_secret,
        &handshake_traffic_client_key,
        &handshake_traffic_client_iv));

    S2N_BLOB_EXPECT_EQUAL(expect_handshake_traffic_server_key, handshake_traffic_server_key);
    S2N_BLOB_EXPECT_EQUAL(expect_handshake_traffic_server_iv, handshake_traffic_server_iv);

    /* This test checks the new secret produced by the s2n_tls13_update_application_traffic_secret
     * is the same one that is produced by openssl when starting with the same application secret.
     */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS13;
        server_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

        /* get tls13 key context */
        s2n_tls13_connection_keys(keys, server_conn);

        s2n_stack_blob(app_secret_update, keys.size, S2N_TLS13_SECRET_MAX_LEN);

        /* Derives next generation of traffic secret */
        EXPECT_SUCCESS(s2n_tls13_update_application_traffic_secret(&keys, &application_secret, &app_secret_update));

        /* Check the new secret is what was expected */
        S2N_BLOB_EXPECT_EQUAL(app_secret_update, updated_application_secret);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Verify binder_key calculation matches session resumption values from
     * https://tools.ietf.org/html/rfc8448#section-4 */
    {
        S2N_BLOB_FROM_HEX(resumption_secret,
            "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
        S2N_BLOB_FROM_HEX(expected_resumption_early_secret,
            "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c");
        S2N_BLOB_FROM_HEX(expected_binder_key,
            "69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256");

        DEFER_CLEANUP(struct s2n_psk test_psk, s2n_psk_wipe);
        EXPECT_OK(s2n_psk_init(&test_psk, S2N_PSK_TYPE_RESUMPTION));
        EXPECT_SUCCESS(s2n_psk_set_secret(&test_psk, resumption_secret.data, resumption_secret.size));

        DEFER_CLEANUP(struct s2n_tls13_keys test_keys, s2n_tls13_keys_free);
        EXPECT_SUCCESS(s2n_tls13_keys_init(&test_keys, test_psk.hmac_alg));

        EXPECT_SUCCESS(s2n_tls13_derive_binder_key(&test_keys, &test_psk));

        S2N_BLOB_EXPECT_EQUAL(test_keys.extract_secret, expected_resumption_early_secret);
        S2N_BLOB_EXPECT_EQUAL(test_keys.derive_secret, expected_binder_key);
    }

    /* Test s2n_tls13_derive_early_secret produces the correct secret when a psk is set. Values
     * are taken from https://tools.ietf.org/html/rfc8448#section-4 */
    {
        S2N_BLOB_FROM_HEX(resumption_early_secret,
            "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c");
        S2N_BLOB_FROM_HEX(expected_derived_secret,
            "5f1790bbd82c5e7d376ed2e1e52f8e6038c9346db61b43be9a52f77ef3998e80");

        DEFER_CLEANUP(struct s2n_psk test_psk = { 0 }, s2n_psk_wipe);
        EXPECT_OK(s2n_psk_init(&test_psk, S2N_PSK_TYPE_RESUMPTION));
        test_psk.early_secret = resumption_early_secret;

        DEFER_CLEANUP(struct s2n_tls13_keys test_keys = { 0 }, s2n_tls13_keys_free);
        EXPECT_SUCCESS(s2n_tls13_keys_init(&test_keys, test_psk.hmac_alg));

        EXPECT_SUCCESS(s2n_tls13_derive_early_secret(&test_keys, &test_psk));

        S2N_BLOB_EXPECT_EQUAL(test_keys.derive_secret, expected_derived_secret);
    }

    /* s2n_tls13_derive_early_secret will error using a psk with an empty early secret */
    {
        struct s2n_blob empty_blob = { .data = NULL, .size = 0 };

        DEFER_CLEANUP(struct s2n_psk test_psk = { 0 }, s2n_psk_wipe);
        EXPECT_OK(s2n_psk_init(&test_psk, S2N_PSK_TYPE_RESUMPTION));
        test_psk.early_secret = empty_blob;

        DEFER_CLEANUP(struct s2n_tls13_keys test_keys = { 0 }, s2n_tls13_keys_free);
        EXPECT_SUCCESS(s2n_tls13_keys_init(&test_keys, test_psk.hmac_alg));

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_derive_early_secret(&test_keys, &test_psk), S2N_ERR_SAFETY);
    }

    /* Test s2n_tls13_derive_early_traffic_secret */
    {
        /** ClientHello record needed for hash.
         *
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *# {client}  send handshake record:
         *#
         *#    payload (512 octets):  01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c ff
         *#       93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41 9d 78 76
         *#       48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00
         *#       09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12
         *#       00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00
         *#       26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34
         *#       6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b 00 2a 00
         *#       00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02
         *#       03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02
         *#       02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 57 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00
         *#       00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70
         *#       ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9
         *#       82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6
         *#       1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0
         *#       37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5
         *#       90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5
         *#       ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d
         *#       e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 fa d6 aa
         *#       cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e f5 e8 8d
         *#       ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d
         */
        S2N_BLOB_FROM_HEX(payload,   "01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c ff \
                  93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41 9d 78 76 \
                  48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00 \
                  09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 \
                  00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00 \
                  26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34 \
                  6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b 00 2a 00 \
                  00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 \
                  03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 \
                  02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 57 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 \
                  00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 \
                  ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 \
                  82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 \
                  1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 \
                  37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 \
                  90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 \
                  ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d \
                  e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 fa d6 aa \
                  cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e f5 e8 8d \
                  ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d")

        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *# {client}  derive secret "tls13 c e traffic":
         *#
         *#    PRK (32 octets):  9b 21 88 e9 b2 fc 6d 64 d7 1d c3 29 90 0e 20 bb
         *#       41 91 50 00 f6 78 aa 83 9c bb 79 7c b7 d8 33 2c
         **/
        S2N_BLOB_FROM_HEX(prk,  "9b 21 88 e9 b2 fc 6d 64 d7 1d c3 29 90 0e 20 bb \
                  41 91 50 00 f6 78 aa 83 9c bb 79 7c b7 d8 33 2c");
        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *#
         *#    hash (32 octets):  08 ad 0f a0 5d 7c 72 33 b1 77 5b a2 ff 9f 4c 5b
         *#       8b 59 27 6b 7f 22 7f 13 a9 76 24 5f 5d 96 09 13
         */
        S2N_BLOB_FROM_HEX(hash,  "08 ad 0f a0 5d 7c 72 33 b1 77 5b a2 ff 9f 4c 5b \
                  8b 59 27 6b 7f 22 7f 13 a9 76 24 5f 5d 96 09 13");
        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *#
         *#    info (53 octets):  00 20 11 74 6c 73 31 33 20 63 20 65 20 74 72 61
         *#       66 66 69 63 20 08 ad 0f a0 5d 7c 72 33 b1 77 5b a2 ff 9f 4c 5b
         *#       8b 59 27 6b 7f 22 7f 13 a9 76 24 5f 5d 96 09 13
         *#
         *#    expanded (32 octets):  3f bb e6 a6 0d eb 66 c3 0a 32 79 5a ba 0e
         *#       ff 7e aa 10 10 55 86 e7 be 5c 09 67 8d 63 b6 ca ab 62
         */
        S2N_BLOB_FROM_HEX(expanded,  "3f bb e6 a6 0d eb 66 c3 0a 32 79 5a ba 0e \
                  ff 7e aa 10 10 55 86 e7 be 5c 09 67 8d 63 b6 ca ab 62");

        DEFER_CLEANUP(struct s2n_tls13_keys test_keys = { 0 }, s2n_tls13_keys_free);
        EXPECT_SUCCESS(s2n_tls13_keys_init(&test_keys, S2N_HMAC_SHA256));
        test_keys.extract_secret = prk;

        DEFER_CLEANUP(struct s2n_hash_state client_hello_hash = {0}, s2n_hash_free);
        EXPECT_SUCCESS(s2n_hash_new(&client_hello_hash));
        EXPECT_SUCCESS(s2n_hash_init(&client_hello_hash, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&client_hello_hash, payload.data, payload.size));

        /* Sanity check: Verify the hash is correct */
        s2n_tls13_key_blob(actual_hash, test_keys.size);
        DEFER_CLEANUP(struct s2n_hash_state hkdf_hash_copy, s2n_hash_free);
        EXPECT_SUCCESS(s2n_hash_new(&hkdf_hash_copy));
        EXPECT_SUCCESS(s2n_hash_copy(&hkdf_hash_copy, &client_hello_hash));
        EXPECT_SUCCESS(s2n_hash_digest(&hkdf_hash_copy, actual_hash.data, actual_hash.size));
        S2N_BLOB_EXPECT_EQUAL(actual_hash, hash);

        s2n_tls13_key_blob(early_traffic_secret, test_keys.size);
        EXPECT_SUCCESS(s2n_tls13_derive_early_traffic_secret(&test_keys, &client_hello_hash, &early_traffic_secret));
        S2N_BLOB_EXPECT_EQUAL(early_traffic_secret, expanded);
    }

    END_TEST();
}
