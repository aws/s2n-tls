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

#include "stuffer/s2n_stuffer.h"

#include "tests/s2n_test.h"
#include "tests/testlib/s2n_testlib.h"

#include "tls/s2n_kem.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_blob.h"

/* This fuzz test uses the below private key which is the first key from tests/unit/kats/sike_p503.kat, the valid
 * ciphertext generated with the public key was copied to corpus/s2n_sike_r1_fuzz_test/valid_ciphertext */
static const char valid_private_key[] = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148038626ED79D451140800E03B59B956F8210E556067407D13DC90FA9E8B872BFB0F0999A0BB085F85FDA70D04B8FCAE5A30989947F1E32E4BC4675C834CA22CBA08AE692935EC1C8AF2B5BF377EC17E79D09D57DB5828C6F6E1C1A64D0F30AF3D2F76D9D329108E01D027D856EC44B23A437872D538F2C26E48723E2F8E46A2E7A364C92D997C7B801ADA199EEFFBAB1161B29EC7CB4440DA0E75407F4CE02E37BDFB23154C513BD30CFA5F04D2E253357CBDEBCF6F539965C8B8B5F350A50526AD1B350A0220394AA33B18EB3E765F059FA7CB5585A9D18C8B198A07DA0E9CCEC61D6F43A4661CA6D8175C23A8C86DD30409607D6EBFA3639CDFD12599F9BB073AAEA9A1CC95FF0D50839049EDFAE95FD10DD4F27EC3C6921FA96DCB0366D9C086A8E8ED15390C4827E5672D167EE238229B188C0590E1FA38E8A74D34B6D17ECA1A64EA76AD65413F147DC43A762D69D072DADF573C13A7C983F9362D59DC6E37704BA0F15637CF6BEDBBD8C1051366FE4C21E03CC55964C0E24F6F8D738DC763B7E443122C63751F6D8130EADA4203A9671865F8D459035EAC2E";

static struct s2n_kem_keypair server_kem_keys = {.negotiated_kem = &s2n_sike_p503_r1};
static struct s2n_stuffer private_key_stuffer = {{0}};

static void s2n_fuzz_atexit()
{
    s2n_stuffer_free(&private_key_stuffer);
    s2n_cleanup();
}

int LLVMFuzzerInitialize(const uint8_t *buf, size_t len)
{
    GUARD(s2n_init());
    GUARD(s2n_stuffer_alloc_ro_from_hex_string(&private_key_stuffer, valid_private_key));
    GUARD(atexit(s2n_fuzz_atexit));

    server_kem_keys.private_key.size = s2n_sike_p503_r1.private_key_length;
    server_kem_keys.private_key.data = s2n_stuffer_raw_read(&private_key_stuffer, s2n_sike_p503_r1.public_key_length);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    struct s2n_blob server_shared_secret = {0};
    struct s2n_blob ciphertext = {0};
    GUARD(s2n_alloc(&ciphertext, len));

    /* Need to memcpy since blobs expect a non-const value and LLVMFuzzer does expect a const */
    memcpy_check(ciphertext.data, buf, len);

    /* Run the test, don't use GUARD since the memory needs to be cleaned up and decapsulate will most likely fail */
    s2n_kem_decapsulate(&server_kem_keys, &server_shared_secret, &ciphertext);

    GUARD(s2n_free(&ciphertext));

    /* The above s2n_kem_decapsulate could fail before ever allocating the server_shared_secret */
    if (server_shared_secret.allocated) {
        GUARD(s2n_free(&server_shared_secret));
    }
    return 0;
}
