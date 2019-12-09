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

#include <string.h>

#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hmac.h"
#include "crypto/s2n_hkdf.h"
#include "crypto/s2n_tls13_keys.h"

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

    S2N_BLOB_FROM_HEX(expect_handshake_traffic_server_key,
        "3fce516009c21727d0f2e4e86ee403bc");

    S2N_BLOB_FROM_HEX(expect_handshake_traffic_server_iv,
        "5d313eb2671276ee13000b30");

    S2N_BLOB_FROM_HEX(expect_derived_client_handshake_secret_digest,
        "860c06edc07858ee8e78f0e7428c58ed"
        "d6b43f2ca3e6e95f02ed063cf0e1cad8");

    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_tls13_keys secrets = {0}, s2n_tls13_keys_free);

    EXPECT_SUCCESS(s2n_tls13_keys_init(&secrets, S2N_HMAC_SHA256));

    /* Derive Early Secrets */
    EXPECT_SUCCESS(s2n_tls13_derive_early_secrets(&secrets));

    S2N_BLOB_EXPECT_EQUAL(secrets.extract_secret, expected_early_secret);
    S2N_BLOB_EXPECT_EQUAL(secrets.derive_secret, expect_derived_handshake_secret);

    DEFER_CLEANUP(struct s2n_hash_state hash_state, s2n_hash_free);
    EXPECT_SUCCESS(s2n_hash_new(&hash_state));
    EXPECT_SUCCESS(s2n_hash_init(&hash_state, secrets.hash_algorithm));
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, client_hello.data, client_hello.size));
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, server_hello.data, server_hello.size));

    s2n_tls13_key_blob(client_handshake_secret, secrets.size);
    s2n_tls13_key_blob(server_handshake_secret, secrets.size);

    DEFER_CLEANUP(struct s2n_hash_state hash_state_copy, s2n_hash_free);
    EXPECT_SUCCESS(s2n_hash_new(&hash_state_copy));
    EXPECT_SUCCESS(s2n_hash_copy(&hash_state_copy, &hash_state));

    /* Derive Handshake Secrets */
    EXPECT_SUCCESS(s2n_tls13_derive_handshake_secrets(&secrets, &ecdhe, &hash_state_copy, &client_handshake_secret, &server_handshake_secret));

    /* this checks that the original hash state can still be used to derive a hash without being affected by the derive function */
    s2n_tls13_key_blob(client_server_hello_hash, secrets.size);
    EXPECT_SUCCESS(s2n_hash_digest(&hash_state_copy, client_server_hello_hash.data, client_server_hello_hash.size));
    S2N_BLOB_EXPECT_EQUAL(expect_derived_client_handshake_secret_digest, client_server_hello_hash);
    EXPECT_SUCCESS(s2n_hash_free(&hash_state_copy));

    S2N_BLOB_EXPECT_EQUAL(expect_derived_client_handshake_secret, client_handshake_secret);
    S2N_BLOB_EXPECT_EQUAL(expect_derived_server_handshake_secret, server_handshake_secret);
    S2N_BLOB_EXPECT_EQUAL(expect_derived_master_secret, secrets.derive_secret);

    /* Derive Application Secrets */
    s2n_tls13_key_blob(client_application_secret, secrets.size);
    s2n_tls13_key_blob(server_application_secret, secrets.size);

    /* Update handshake transcribe hashes */
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, encrypted_extensions.data, encrypted_extensions.size));
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, certificate.data, certificate.size));
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, certificate_verify.data, certificate_verify.size));

    /* Derive server finished key */
    s2n_stack_blob(server_finished_key, secrets.size, S2N_TLS13_SECRET_MAX_LEN);
    EXPECT_SUCCESS(s2n_tls13_derive_finished_key(&secrets, &server_handshake_secret, &server_finished_key));

    s2n_tls13_key_blob(server_finished_verify, secrets.size);
    EXPECT_SUCCESS(s2n_tls13_calculate_finished_mac(&secrets, &server_finished_key, &hash_state, &server_finished_verify));

    S2N_BLOB_EXPECT_EQUAL(expect_server_finished_verify, server_finished_verify);

    /* Update handshake hashes with Server Finished */
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, server_finished.data, server_finished.size));

    s2n_stack_blob(client_finished_key, secrets.size, S2N_TLS13_SECRET_MAX_LEN);
    EXPECT_SUCCESS(s2n_tls13_derive_finished_key(&secrets, &client_handshake_secret, &client_finished_key));

    s2n_tls13_key_blob(client_finished_verify, secrets.size);
    EXPECT_SUCCESS(s2n_tls13_calculate_finished_mac(&secrets, &client_finished_key, &hash_state, &client_finished_verify));

    /* Test Client Finished MAC hash */
    S2N_BLOB_EXPECT_EQUAL(expect_client_finished_verify, client_finished_verify);

    EXPECT_SUCCESS(s2n_tls13_derive_application_secrets(&secrets, &hash_state, &client_application_secret, &server_application_secret));
    S2N_BLOB_EXPECT_EQUAL(expect_extract_master_secret, secrets.extract_secret);

    S2N_BLOB_EXPECT_EQUAL(expect_derived_client_application_traffic_secret, client_application_secret);
    S2N_BLOB_EXPECT_EQUAL(expect_derived_server_application_traffic_secret, server_application_secret);

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

    END_TEST();
}
