/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdlib.h>
#include <string.h>

#include "testlib/s2n_testlib.h"

#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_dhe.h"
#include "crypto/s2n_fips.h"

static uint8_t unmatched_private_key[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpQIBAAKCAQEA6ddvtO6DbX5GLrWeXD2jufmR6lvYuzwpIHbDf0RQr2AT50wf\n"
    "vV+sMYVa/d4g68tqtihH691tqzKevVc25LXM0a0f0NfnrNibyA1/66CwFQsyy1j2\n"
    "U90BdguI/ZxqEV58ee/PzerOoS5d/rgBALzGwwYwyvlzr35KGjfRZ4XOFoToKnkN\n"
    "0mR44firCvb7dJ53QRXoPbkYpQQQ3vMWMOtDZoPsvP0dJJ50B7LaFL6nbOyJmZ2T\n"
    "evaAov1Nuk5QSrZf2icpuQVXxuu2xLmTNL25OUiV3t7ZjiLtrOZrmrIzv8/sLcWp\n"
    "VJcFWFoKizmjvpDfD086a9c81vo4kqgD/RZ9dQIDAQABAoIBAQDBNUzJ3MxgupW4\n"
    "YD2BDzjpH2jNj6fKRBHjDd3HmKVl0eeAE2iiKpt2qy2cVl0zFfaMnUmXe3PyoLeB\n"
    "z76+R+v8TqPcBZgZOzuzllvcTv9N09vbIh0c+50KcMt2aDdHNJ96jIdRJzIlAM+O\n"
    "9290sYU0fDfybRuFo74MXZQ6idbWyNMjXEv2oPrmvMmOHm10sz9BCXWFUpDpDFKD\n"
    "8xgw1GZ1QeHITWoQXMI2uJUFFj2hYbRAl6f8cMXVjUipmMNpfJk4CbtEdSMPkjrz\n"
    "XgIVrMCorCiaLuVQgSQCHB01n8ETM6R9PYSgMSg3RYYqKq4N0nvREUf4VvKV8JOY\n"
    "EGzNgq3BAoGBAPvHPoCKQawLEr4jE5ITMqhZXlBXh8aU7LetjSY1BfnsiH43eg1n\n"
    "186lfOX0r1I2KkVZTehZohkEo8xeEpc+XMdux1z0mX2uz1tfmHl838sRaTBs1JZ0\n"
    "slkBrASfDdOnLlHCMhRmFEEnA0eelNYCiy/Ak0UX7NpuhZ3bh2jGemixAoGBAO3D\n"
    "MupFbCl64AFEuLCA3wSFRhG82AScYAF1txoTM01V/kqy66j2jJsqMXkVcyBcLBkJ\n"
    "5ozW4kIKkh0dYtIjDpsnXKBK/kVcvJN+60hwVnAMFFJPlRCdejkKSsSe9xod+FzU\n"
    "DvwWLpLaO3sFtykGHelFbzMDB6FaZQFSfSMsNhIFAoGBAKaNafor+z9s38wpdfPG\n"
    "gVc+LxakoGur7l+fDeU9ZCOs5ang1vtxOyA29sVDtIqEzDet2MygJou4NwalIFUu\n"
    "ar9+t6D1KWgrsH24YivTgFNbxCLFi2ev8J7SbVFtSf8983UgKnK2CCYFQbUp4Tkk\n"
    "26AOGx20svjX7cm8A/o6eZUxAoGBANtedXSnNuOSpmklMc5QKPRvzrWA6kJe0Umn\n"
    "hZf+TSA2jlf3eu07BYIITPst6jnaMSms89XQUZOjUyqfuVSu2cQXbiPK7Y2rwaXI\n"
    "vWbplybsTjefi6Z31ZQZReDh1pV3P3bOhUDban898RFRtauZJDHdSXrkeb7Ku1Sb\n"
    "+i9glEbNAoGAJngXJZ2djyzCxYtSNyUFP8AZfmSy+vmHVCCri1FCoFfj9D1HTw4h\n"
    "G0guyN3/Qm51gJVeBTOu/dtoA5JAZi6CRyNuhClLCqV+jGsUr9xyMzA+t/JHVr+0\n"
    "XQhx4wqVYQs2852qaJg+wYUi50FtRT6hLyDQmg9ttvS4YIwMTdVzl2Q=\n"
    "-----END RSA PRIVATE KEY-----\n";

int main(int argc, char **argv)
{
    struct s2n_stuffer certificate_in, certificate_out;
    struct s2n_stuffer dhparams_in, dhparams_out;
    struct s2n_stuffer rsa_key_in, rsa_key_out;
    struct s2n_blob b;
    char *leaf_cert_pem;
    char *cert_chain_pem;
    char *private_key_pem;
    char *dhparams_pem;
    struct s2n_cert_chain_and_key *chain_and_key;

    BEGIN_TEST();

    EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(leaf_cert_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_in, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_out, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&rsa_key_in, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&rsa_key_out, S2N_MAX_TEST_PEM_SIZE));

    EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_LEAF_CERT, leaf_cert_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));

    b.data = (uint8_t *) leaf_cert_pem;
    b.size = strlen(leaf_cert_pem) + 1;
    EXPECT_SUCCESS(s2n_stuffer_write(&certificate_in, &b));

    b.data = (uint8_t *) private_key_pem;
    b.size = strlen(private_key_pem) + 1;
    EXPECT_SUCCESS(s2n_stuffer_write(&rsa_key_in, &b));

    b.data = (uint8_t *) dhparams_pem;
    b.size = strlen(dhparams_pem) + 1;
    EXPECT_SUCCESS(s2n_stuffer_write(&dhparams_in, &b));

    EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));
    EXPECT_SUCCESS(s2n_stuffer_private_key_from_pem(&rsa_key_in, &rsa_key_out));
    EXPECT_SUCCESS(s2n_stuffer_dhparams_from_pem(&dhparams_in, &dhparams_out));

    struct s2n_pkey priv_key;
    struct s2n_pkey pub_key;
    s2n_pkey_type pkey_type;

    b.size = s2n_stuffer_data_available(&certificate_out);
    b.data = s2n_stuffer_raw_read(&certificate_out, b.size);
    EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&pub_key, &pkey_type, &b));

    b.size = s2n_stuffer_data_available(&rsa_key_out);
    b.data = s2n_stuffer_raw_read(&rsa_key_out, b.size);
    EXPECT_SUCCESS(s2n_asn1der_to_private_key(&priv_key, &b));

    EXPECT_SUCCESS(s2n_pkey_match(&pub_key, &priv_key));

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    struct s2n_dh_params dh_params;
    b.size = s2n_stuffer_data_available(&dhparams_out);
    b.data = s2n_stuffer_raw_read(&dhparams_out, b.size);
    EXPECT_SUCCESS(s2n_pkcs3_to_dh_params(&dh_params, &b));

    EXPECT_SUCCESS(s2n_config_add_dhparams(config, dhparams_pem));

    /* Try signing and verification with RSA */
    uint8_t inputpad[] = "Hello world!";
    struct s2n_blob signature;
    struct s2n_hash_state tls10_one, tls10_two, tls12_one, tls12_two;

    EXPECT_SUCCESS(s2n_alloc(&signature, s2n_pkey_size(&pub_key)));
    
    if (s2n_hash_is_available(S2N_HASH_MD5_SHA1)) {
        /* TLS 1.0 use of RSA with DHE is not permitted when FIPS mode is set */
        EXPECT_SUCCESS(s2n_hash_new(&tls10_one));
        EXPECT_SUCCESS(s2n_hash_new(&tls10_two));

        EXPECT_SUCCESS(s2n_hash_init(&tls10_one, S2N_HASH_MD5_SHA1));
        EXPECT_SUCCESS(s2n_hash_init(&tls10_two, S2N_HASH_MD5_SHA1));

        EXPECT_SUCCESS(s2n_hash_update(&tls10_one, inputpad, sizeof(inputpad)));
        EXPECT_SUCCESS(s2n_hash_update(&tls10_two, inputpad, sizeof(inputpad)));
        EXPECT_SUCCESS(s2n_pkey_sign(&priv_key, &tls10_one, &signature));
        EXPECT_SUCCESS(s2n_pkey_verify(&pub_key, &tls10_two, &signature));

        EXPECT_SUCCESS(s2n_hash_free(&tls10_one));
        EXPECT_SUCCESS(s2n_hash_free(&tls10_two));
    }

    /* TLS 1.2 use of RSA with DHE is permitted for FIPS and non-FIPS */
    EXPECT_SUCCESS(s2n_hash_new(&tls12_one));
    EXPECT_SUCCESS(s2n_hash_new(&tls12_two));

    EXPECT_SUCCESS(s2n_hash_init(&tls12_one, S2N_HASH_SHA1));
    EXPECT_SUCCESS(s2n_hash_init(&tls12_two, S2N_HASH_SHA1));

    EXPECT_SUCCESS(s2n_hash_update(&tls12_one, inputpad, sizeof(inputpad)));
    EXPECT_SUCCESS(s2n_hash_update(&tls12_two, inputpad, sizeof(inputpad)));
    EXPECT_SUCCESS(s2n_pkey_sign(&priv_key, &tls12_one, &signature));
    EXPECT_SUCCESS(s2n_pkey_verify(&pub_key, &tls12_two, &signature));

    EXPECT_SUCCESS(s2n_hash_free(&tls12_one));
    EXPECT_SUCCESS(s2n_hash_free(&tls12_two));

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_config_free(config));

    /* Mismatched public/private key should fail */
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_FAILURE(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, (char *)unmatched_private_key));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_config_free(config));

    EXPECT_SUCCESS(s2n_dh_params_free(&dh_params));
    EXPECT_SUCCESS(s2n_pkey_free(&priv_key));
    EXPECT_SUCCESS(s2n_pkey_free(&pub_key));
    EXPECT_SUCCESS(s2n_free(&signature));
    EXPECT_SUCCESS(s2n_stuffer_free(&certificate_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&certificate_out));
    EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_out));
    EXPECT_SUCCESS(s2n_stuffer_free(&rsa_key_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&rsa_key_out));
    free(cert_chain_pem);
    free(leaf_cert_pem);
    free(private_key_pem);
    free(dhparams_pem);

    END_TEST();
}
