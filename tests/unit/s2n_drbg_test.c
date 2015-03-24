/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <inttypes.h>
#include <fcntl.h>
#include <s2n.h>

#include "crypto/s2n_drbg.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"
#include "utils/s2n_timer.h"

#include "testlib/s2n_testlib.h"


/* Test vectors are taken from http://csrc.nist.gov/groups/STM/cavp/documents/drbg/drbgtestvectors.zip
 * - drbgvectors_no_reseed/CTR_DRBG.txt :
 * [AES-128 no df]
 * [PredictionResistance = False]
 * [EntropyInputLen = 256]
 * [NonceLen = 0]
 * [PersonalizationStringLen = 256]
 * [AdditionalInputLen = 0]
 * [ReturnedBitsLen = 512]
 */

struct s2n_stuffer nist_reference_entropy;
const char nist_reference_entropy_hex[] =
"cee23de86a69c7ef57f6e1e12bd16e35e51624226fa19597bf93ec476a44b0f2"
"b09eb4a82a39066ec945bb7c6aef6a0682a62c3e674bd900297d4271a5f25b49"
"0bbc898f8daf3f12fc009c846fe2cea22f683a432eea297257312d5a44bac131"
"3ea1f3fb153636c33982464f0e5b0daeba59c3f1ee91a612c4f6a9dcfcd0a978"
"b6b2033e382decd21e4eabd8f1177761d06a12bae1cfed0059b7e16bd9bab8d7"
"acc465d1bf94ccdeec06c74c812db3a993c408b5c2ef7ebe9bdeb6a1a51976a7"
"14b33415d2321fbb10a768ced712c8999ff2f19b63264a81adc2fdc16370b185"
"5a83af23cafb30e3a18e28651b3c1bd01813c44216e7e44b790d6664e2c3839a"
"1dc24dd9d6a405a007bd082cfbdbd863185e072b67d663b14d7e8f16900cfce6"
"ecb7e61a4792a2115213d141d20710e8a3212d7847dd53dfa5d4d7777d10d97e"
"e55727c590ec3ac108f4e5fec39a2d34bf89aee4e215dcc970db8ae8f6a0e4a8"
"c380dafd84f2782b7539ca1c3ad9715fe6b1805310a578afcffc9210ac127ded"
"f158210535a404f6cb4f9550b3f26e3f777a9faa164774749f48ef4a8ce09449"
"973a99b7e03b393ef689af8cb90d7436cae10e4814814aed342dd38e2a7346e3"
"22d1d8c8bde76a239d032804717face16d77b51170d0f53ccbcca4eaff4fb315";
int entropy_fd = -1;

const char nist_reference_personalization_strings_hex[] =
"a2ef16f226ea324f23abd59d5e3c660561c25e73638fe21c87566e86a9e04c3e"
"a3b768adcfe76d61c972d900da8dffeeb2a42e740247aa719ed1c924d2d10bd4"
"8d34be9d8110b84b02a60508deae773c1a808f4e2a0ec81747ae2ec923fe99a9"
"ea8671fc9c02584d69af91de2adacec1408d91d512718945ed1e7dc0b620b323"
"c99a49132543fce49b804e9f417d22e49c460bc4e60a6d36701fea561b93203d"
"77278d47a169c559518d46ffb23aa594efdaebb067c48d4a392f60b94cc15b36"
"029b48805285349c292a99ee68fcefda1f61dd60a09f4616cb2efe4f8b140056"
"d0f108ae7c65e16cfa13e5582204eb8cd6ebb08f1f6a5d476c275247c1a83eb5"
"0eca85ddcb6f38ff3683968ef98b52408428dcae2ec3b0fa4c68906c1b6481cd"
"bf09235d30cd69ada285948fe1be2e0c4e145ac8485d12ca7b8239136da1c638"
"ade3d28a8e43aab8fd31dec8bdbe5c41c0b3f7f69a2d0aada5608ab0e57c8bb0"
"b298533d9c74a0d9b9aa0d82edc434002b4d1372318c2865b7700a5b7ebeabf0"
"d56fa873cc762f64b3ab31b6291e247efca71fca90453cfff1f2b0b3e265c475"
"300d3d2adbac6d7ddadde07e08b0d72b5b39ff36031e81d8303958242e3cf03f"
"5d3a7d40fdf95b98454bca03c6fcbf6abf3807de75171b55bab2db5a3f5f12f2";

const char nist_reference_values_hex[] =
"875ca09f6c98d419cbed4078b21602b4" "c010928566ea8652633897ded2831d65" "5f682429696cdb12884216d9a1dcf1c3"
"338ad88405bad0e3448449ec0691aee5" "57e22ef1b938717ea709545561324899" "7a8d092212835c387b4528d90bd35c84"
"36606fc3645242f7e3b7c12a16f6a6e0" "0c382a9328ffeea7e5fbf1dcd776aea8" "2f2e99151618ba02723b4d51b00450cd"
"f95c88ea9c568cc5dac016a53b42e423" "c7f672a6e3df3eb894c52c6b486b77a2" "c64bbe1dc0ddb99b3764c844d58db110"
"4fa4c3b0677323a4da80c984b39b6692" "9c312222a1084439c88e3cbaa081ccc3" "b4fa611db8f927779e1ea5db7811088b"
"7f9639cbc59d506651d914a1986ad3e9" "494a0111f0c06ad9b3d8da826766823e" "cfa4bd861f4497974504327e2478b7da"
"831bf635a30faf0595c4c13799d64fab" "d0539f883731c0f79a143fff1f8a5d2c" "d8fd762c6a86747079c43957a3ee653e"
"cd70ae03693b1a9ee602f69a52d94357" "6d84412dadc384eb1d05873c7e4c8a9c" "b22419a9ea593101ad32c92c1b65556a"
"9ffe014b29a370d9f23eddc3fada8353" "6821940f64e3d5168bb9383f01823c46" "1eefe63669a84ff63edffd50b1fada6f"
"eebdad7e6f36e2872d7e2cdd6103e13e" "da383ed604025ec80ed1351812e95cbe" "f76e443d6edc4a710a0ed7a538877f38"
"7cb283dc188e75f62693c2e1626e9160" "788f431f00030c34e95169fbb8c84854" "a1d6fdbcaf60e1430fdbde9feaa6dbe5"
"ce7449ef419ff3588ba45af2a31e2865" "01bafe506229675b0260d5c3fd3b43dc" "8e3f8b7c2064d72f2315a9f9fe5a0de1"
"88555aaee6b4eb199d929d401f37ae44" "f2e2ffa357d16ad12d7ad979278f60cd" "8c50902519598407e3095a5fdf31f0e9"
"92502bb0772968a7f73c491375fd48a4" "baa517ead345078a5b83566f9963e2c0" "7adb91d7090edea7f7a76d272523469e"
"d1c7680165714dfb8256bd09b1a25f9f" "c30fb4bf77be6ff6bf71bd6cf171791b" "c7aff7a54d51dd50a72948ceed18ac16";

const char nist_reference_keys_hex[] =
"34efd7d4b6fdc5c14222292bd10a4d6a" "380112415ed0cfa4e910c91f27adf396" "0ea90501784f40ba056a06e859f64249"
"4bcb20cb1fa05b6e36487f2b1485d0b2" "7562c4aa6ec867303135c6861f9cde2c" "6a2905ef7f6bf3c58b3792de4853b56e"
"de6acbdcf6c1b738c8d984db15abfcc4" "7e192a78ac3ddcb62e614374b9135f04" "b3f3e280ca37335afa1f1c6d3d73d1e3"
"8cc57ec9734a5eef6652cac680668635" "f948c32d0fdaf1032dd9acb6e63a4af7" "681b7053b69a372ace849166f611adc4"
"27cab6e3e7102057b3b1f810148d10df" "c4f1f7a8651a0d4af90865723c26b9ab" "9e390b4283ce55b60f41f632690701dc"
"83011458e48339e68bf49ce497f05367" "4621f8de248511977d7b06b493b4416e" "50031cf538c89202450f884b0f1a4e44"
"4eca805b7ac91b460ff2ec771b096219" "c895f5287e23cb2c37e221277a7f437f" "e27ab5108f51958b330dd0a7f7d52731"
"d2905b434ce0e1ee6de2d06a9ddfb506" "b33c86a31af2d92b932fa7c7871757f3" "9ebd8b882f220d55a1f24b205d098919"
"4bea34cae7b50d3e074183f5a6b7cf79" "66cca59280ad0974623dd6766b53b3ee" "6dd7b3a0944cfad4f0469e1d5920fe6c"
"0b5c39898d21fbddc6e95899975e7bbe" "4de0733f3a65bd04b7566ceca51e9dd6" "135a9997b91f845bf19e19a51a36c73e"
"10560981e4d1a018c3ba2661dac3342f" "51edca3ff99e44e9cc261dea1aa163a9" "5f87fef03cd4e58aa50d79c0cd652ec1"
"29fa750ee2f8e893faecdac973fa0005" "6f85bf8c36bccae8375bf86e58efd243" "dc053bd873a0550f259090b4a397292d"
"7cd575b803ac1bf34e9bb9b13e0b0f1b" "7a98b2c560614f7a6abae16f6132fdb0" "02fabefd18eb8792081c18d08806cd7d"
"ffd55853c1e964221a2b52a5155ae647" "7f33de8d70be01e0b759e71f1ad4b330" "ab2a57ccfd9f7f4e39419cd8e172c15a"
"27095946ba6001daee37ff50136456d1" "a28d0bdd09dea0b48dba8432473b6f96" "1787241c6975f759efbd923f825cf444";

const char nist_reference_returned_bits_hex[] =
"2a76d71b329f449c98dc08fff1d205a2fbd9e4ade120c7611c225c984eac8531288dd3049f3dc3bb3671501ab8fbf9ad49c86cce307653bd8caf29cb0cf07764"
"5a1c26803f3ffd4daf32042fdcc32c3812bb5ef13bc208cef82ea047d2890a6f5dcecf32bcc32a2585775ac5e1ffaa8de00664c54fe00a7674b985619e953c3a"
"da49e24a6cb1d9e51b98ea6103627d9ad035770b7bdc760606e2b5f35afd13b7a61a4a18fac25258985fa1fb2b88a7cc17278b0539d7cf74f940f008ee2cf4cd"
"2429e7d817cfd4f8500948d2ec2dec02b7d035b4bb986144bb918a31bfd2269e6907c34ac8beab69508869a4f04bc3c23ccfbae5d59eab857ece000d554b273a"
"63626608b446c7d02212209d0a3888e40534864d8f5cd28aaff09505ee5e894751e5cb8467a5d85d87a675b7852724deb0d12038035400c3405fafb1a47f88c8"
"e0e6e417de8fc5d212bdda4c026a13d6eae402874d62c30577ee4c3445ace85479cbc3b55bbbe1573c13f9b0242d7e3f6e7e91d932b3d5a6dca8df43c188ae5e"
"8a69feb26be025a3849bb0b60959717daa59c889c383593d1f8debf58051eb463d07c659cfbe47e94224ba18833b71d95905e0cde785364a87706e31297fb323"
"e64397f0eea0d33d9715bcef2ee7eec22a86e8d066a25e44706dc688c499bd7ef08172c8cf36e3bddf79f2bec136a01aad844930e48a16fe1800d69fb0f4e163"
"156938566fc25d493c1c60d8925819a6e59a2479d75f3efff16d46aada68403140407955c1fd9d2a890bcf67ac9b3b82d1d6cf788fd863da3d41ac6e34f217a0"
"868db5832b2e9c3d2c9794b174b328ed2cc86e41017863eabc4a7c096a487bfe4d67ccf93a5e2c67d88dbd8f1419b2a9f1293e7a70e8e8fe93e2156496b0fa54"
"198742299feecf6083e3a0bef75ac2b93de2defa6525883a55f88247dc6902279f792402faffe4a81213e40facb873cd499e4b0f7f0ff592bc06699db773b899"
"9aec7a5ba3e091e6a6c99e04395af2ab2eeaa1ef089baa51dc23ea31603b899ea298317603354f38fd9c36c2a53a05c1e468c6ae32fe4c3b0056ec0d5eff22b6"
"034b41b2a9a6764e5ed1edb00aea3185fe43eb81b4253e7cade97956fccd9fc5782328fada8ed5208f1d46b1f872e333b9e2f036a51746ccaf39e1a85af8eb23"
"62012842991fe3220f1d961045f028a3b6a729f5a451b8c2ec90e1c1e2b1e4042e97267e1bfa1782a10c3c29509bc8f2adffd3d695861e1594da91702830faf7"
"1007e11f48e3c4813fddd67310db56d67a49fe93e45e61b37ba81485df6a62ee57ca41fa1d987f467c2939790a20421c2b4f70b28fb0b90bbeab1ac0ae884f1a";

/* This function over-rides the s2n internal copy of the same function */
int nist_fake_urandom_data(struct s2n_blob *blob)
{
    /* At first, we use entropy data provided by the NIST test vectors */
    GUARD(s2n_stuffer_read(&nist_reference_entropy, blob));

    return 0;
}

int main(int argc, char **argv)
{
    uint8_t data[256];
    struct s2n_drbg drbg;
    struct s2n_blob blob = {.data = data, .size = 16 };
    struct s2n_timer timer;
    uint64_t drbg_nanoseconds;
    uint64_t urandom_nanoseconds;
    struct s2n_stuffer nist_reference_personalization_strings;
    struct s2n_stuffer nist_reference_returned_bits;
    struct s2n_stuffer nist_reference_keys;
    struct s2n_stuffer nist_reference_values;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_init());

    /* Open /dev/urandom */
    EXPECT_TRUE(entropy_fd = open("/dev/urandom", O_RDONLY));

    /* Convert the hex entropy data into binary */
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&nist_reference_entropy, nist_reference_entropy_hex));
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&nist_reference_personalization_strings, nist_reference_personalization_strings_hex));
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&nist_reference_returned_bits, nist_reference_returned_bits_hex));
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&nist_reference_values, nist_reference_values_hex));
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&nist_reference_keys, nist_reference_keys_hex));

    /* Check everything against the NIST vectors */
    for (int i = 0; i < 14; i++) {
        uint8_t ps[32];
        struct s2n_drbg nist_drbg = { .entropy_generator = nist_fake_urandom_data };
        struct s2n_blob personalization_string = {.data = ps, .size = 32};

        /* Read the next personalization string */
        EXPECT_SUCCESS(s2n_stuffer_read(&nist_reference_personalization_strings, &personalization_string));

        /* Instantiate the DRBG */
        EXPECT_SUCCESS(s2n_drbg_instantiate(&nist_drbg, &personalization_string));

        uint8_t nist_key[16];
        uint8_t nist_v[16];

        GUARD(s2n_stuffer_read_bytes(&nist_reference_keys, nist_key, sizeof(nist_key)));
        GUARD(s2n_stuffer_read_bytes(&nist_reference_values, nist_v, sizeof(nist_v)));

        EXPECT_TRUE(memcmp(nist_key, nist_drbg.key, sizeof(nist_drbg.key)) == 0);
        EXPECT_TRUE(memcmp(nist_v, nist_drbg.v, sizeof(nist_drbg.v)) == 0);

        /* Generate 512 bits (FIRST CALL) */
        uint8_t out[64];
        struct s2n_blob generated = {.data = out, .size = 64 };
        EXPECT_SUCCESS(s2n_drbg_generate(&nist_drbg, &generated));

        GUARD(s2n_stuffer_read_bytes(&nist_reference_keys, nist_key, sizeof(nist_key)));
        GUARD(s2n_stuffer_read_bytes(&nist_reference_values, nist_v, sizeof(nist_v)));

        EXPECT_TRUE(memcmp(nist_key, nist_drbg.key, sizeof(nist_drbg.key)) == 0);
        EXPECT_TRUE(memcmp(nist_v, nist_drbg.v, sizeof(nist_drbg.v)) == 0);

        /* Generate another 512 bits (SECOND CALL) */
        EXPECT_SUCCESS(s2n_drbg_generate(&nist_drbg, &generated));

        GUARD(s2n_stuffer_read_bytes(&nist_reference_keys, nist_key, sizeof(nist_key)));
        GUARD(s2n_stuffer_read_bytes(&nist_reference_values, nist_v, sizeof(nist_v)));

        EXPECT_TRUE(memcmp(nist_key, nist_drbg.key, sizeof(nist_drbg.key)) == 0);
        EXPECT_TRUE(memcmp(nist_v, nist_drbg.v, sizeof(nist_drbg.v)) == 0);

        uint8_t nist_returned_bits[64];
        GUARD(s2n_stuffer_read_bytes(&nist_reference_returned_bits, nist_returned_bits, sizeof(nist_returned_bits)));
        EXPECT_TRUE(memcmp(nist_returned_bits, out, sizeof(nist_returned_bits)) == 0);
    }

    EXPECT_SUCCESS(s2n_drbg_instantiate(&drbg, &blob));

    /* Use the DRBG for 16MB of data */
    EXPECT_SUCCESS(s2n_timer_start(&timer));
    for (int i = 0; i < 1000000; i++) {
        EXPECT_SUCCESS(s2n_drbg_generate(&drbg, &blob));
    }
    EXPECT_SUCCESS(s2n_timer_reset(&timer, &drbg_nanoseconds));

    /* Use urandom for 16MB of data */
    EXPECT_SUCCESS(s2n_timer_start(&timer));
    for (int i = 0; i < 1000000; i++) {
        EXPECT_SUCCESS(s2n_get_urandom_data(&blob));
    }
    EXPECT_SUCCESS(s2n_timer_reset(&timer, &urandom_nanoseconds));

    /* Confirm that the DRBG is faster than urandom */
    EXPECT_TRUE(drbg_nanoseconds < urandom_nanoseconds);

    /* NOTE: s2n_random_test also includes monobit tests for this DRBG */

    /* the DRBG state is 128 bytes, test that we can get more than that */
    blob.size = 129;
    for (int i = 0; i < 10; i++) {
        EXPECT_SUCCESS(s2n_drbg_generate(&drbg, &blob));
    }

    /* Move the DRBG to where it would be just before a reseed */
    EXPECT_EQUAL(drbg.generation, 1);
    drbg.bytes_used = S2N_DRBG_RESEED_LIMIT - 128;
    for (int i = 0; i < 10; i++) {
        EXPECT_SUCCESS(s2n_drbg_generate(&drbg, &blob));
    }
    EXPECT_EQUAL(drbg.generation, 2);

    /* Set up a DRBG against the NIST test vectors */

    END_TEST();
}
