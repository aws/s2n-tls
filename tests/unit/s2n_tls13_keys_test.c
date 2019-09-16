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

#define S2N_BLOB_EXPECT_EQUAL( blob1, blob2 ) do {              \
    EXPECT_EQUAL(blob1.size, blob2.size);                       \
    EXPECT_BYTEARRAY_EQUAL(blob1.data, blob2.data, blob1.size); \
} while (0)

#define S2N_BLOB_FROM_HEX( name, hex )                  \
    struct s2n_stuffer name##_stuffer;                  \
    s2n_stuffer_alloc_ro_from_hex_string(               \
        &name##_stuffer, hex);                          \
    struct s2n_blob name = name##_stuffer.blob;

#define S2N_BLOB_FREE( name ) do {                       \
    EXPECT_SUCCESS(s2n_stuffer_free(&name##_stuffer));   \
} while (0)

int main(int argc, char **argv)
{
    /* TLS 1.3 Test Vectors from https://tools.ietf.org/html/rfc8448 */
    S2N_BLOB_FROM_HEX(expected_early_secret, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
    S2N_BLOB_FROM_HEX(expect_derived_handshake_secret, "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");

    S2N_BLOB_FROM_HEX(client_hello, "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");
    S2N_BLOB_FROM_HEX(server_hello, "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");

    S2N_BLOB_FROM_HEX(ecdhe, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");

    S2N_BLOB_FROM_HEX(expect_derived_client_handshake_secret, "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
    S2N_BLOB_FROM_HEX(expect_derived_server_handshake_secret, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");

    S2N_BLOB_FROM_HEX(expect_derived_master_secret, "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4");
    S2N_BLOB_FROM_HEX(expect_extract_master_secret, "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");

    S2N_BLOB_FROM_HEX(expect_handshake_traffic_server_key, "3fce516009c21727d0f2e4e86ee403bc");
    S2N_BLOB_FROM_HEX(expect_handshake_traffic_server_iv, "5d313eb2671276ee13000b30");

    S2N_BLOB_FROM_HEX(expect_derived_client_handshake_secret_digest, "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");

    BEGIN_TEST();

    struct s2n_tls13_keys secrets;

    EXPECT_SUCCESS(s2n_tls13_keys_init(&secrets, S2N_HMAC_SHA256));

    /* Derive Early Secrets */
    EXPECT_SUCCESS(s2n_tls13_derive_early_secrets(&secrets));

    S2N_BLOB_EXPECT_EQUAL(secrets.current_secret, expected_early_secret);
    S2N_BLOB_EXPECT_EQUAL(secrets.derive_secret, expect_derived_handshake_secret);

    struct s2n_hash_state hash_state;
    EXPECT_SUCCESS(s2n_hash_new(&hash_state));
    EXPECT_SUCCESS(s2n_hash_init(&hash_state, secrets.hash_algorithm));
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, client_hello.data, client_hello.size));
    EXPECT_SUCCESS(s2n_hash_update(&hash_state, server_hello.data, server_hello.size));

    s2n_tls13_key_blob(client_handshake_secret, secrets.size);
    s2n_tls13_key_blob(server_handshake_secret, secrets.size);

    struct s2n_hash_state hash_state_copy;
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

    EXPECT_SUCCESS(s2n_tls13_derive_application_secrets(&secrets, &hash_state, &client_application_secret, &server_application_secret));
    S2N_BLOB_EXPECT_EQUAL(expect_extract_master_secret, secrets.current_secret);

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

    /* Free stuffers */
    S2N_BLOB_FREE(expected_early_secret);
    S2N_BLOB_FREE(expect_derived_handshake_secret);
    S2N_BLOB_FREE(client_hello);
    S2N_BLOB_FREE(server_hello);
    S2N_BLOB_FREE(ecdhe);
    S2N_BLOB_FREE(expect_derived_client_handshake_secret);
    S2N_BLOB_FREE(expect_derived_server_handshake_secret);
    S2N_BLOB_FREE(expect_derived_master_secret);
    S2N_BLOB_FREE(expect_extract_master_secret);
    S2N_BLOB_FREE(expect_handshake_traffic_server_key);
    S2N_BLOB_FREE(expect_handshake_traffic_server_iv);
    S2N_BLOB_FREE(expect_derived_client_handshake_secret_digest);

    END_TEST();
}
