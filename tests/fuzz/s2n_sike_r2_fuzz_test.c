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

/* This fuzz test uses the below private key which is the first key from tests/unit/kats/sike_p434.kat, the valid
 * ciphertext generated with the public key was copied to corpus/s2n_sike_r2_fuzz_test/valid_ciphertext */
static const char valid_private_key[] = "7C9935A0B07694AA0C6D10E4DB6B1ADD91282214654CB55E7C2CACD53919604D5BAC7B23EEF4B315FEEF5E014484D7AADB44B40CC180DC568B2C142A60E6E2863F5988614A6215254B2F5F6F79B48F329AD1A2DED20B7ABAB10F7DBF59C3E20B59A700093060D2A44ACDC0083A53CF0808E0B3A827C45176BEE0DC6EC7CC16461E38461C12451BB95191407C1E942BB50D4C7B25A49C644B630159E6C403653838E689FBF4A7ADEA693ED0657BA4A724786AF7953F7BA6E15F9BBF9F5007FB711569E72ACAB05D3463A458536CAB647F00C205D27D5311B2A5113D4B26548000DB237515931A040804E769361F94FF0167C78353D2630A1E6F595A1F80E87F6A5BCD679D7A64C5006F6191D4ADEFA1EA67F6388B7017D453F4FE2DFE80CCC709000B52175BFC3ADE52ECCB0CEBE1654F89D39131C357EACB61E5F13C80AB0165B7714D6BE6DF65F8DE73FF47B7F3304639F0903653ECCFA252F6E2104C4ABAD3C33AF24FD0E56F58DB92CC66859766035419AB2DF600";

static struct s2n_kem_keypair server_kem_keys = {.negotiated_kem = &s2n_sike_p434_r2};
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

    server_kem_keys.private_key.size = s2n_sike_p434_r2.private_key_length;
    server_kem_keys.private_key.data = s2n_stuffer_raw_read(&private_key_stuffer, s2n_sike_p434_r2.public_key_length);
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
