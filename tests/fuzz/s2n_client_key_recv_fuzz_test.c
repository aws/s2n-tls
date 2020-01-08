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

#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "tls/s2n_kem.h"
#include "tls/s2n_client_key_exchange.h"
#include "tls/s2n_kex.h"

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

static const uint8_t TLS_VERSIONS[] = {S2N_TLS10, S2N_TLS11, S2N_TLS12};

/* Connection setup variables */
char *cert_chain_pem;
char *private_key_pem;
char *dhparams_pem;
struct s2n_config *config;
struct s2n_cert_chain_and_key *chain_and_key;
struct s2n_cert_chain_and_key *cert;
struct s2n_cipher_suite **test_suites;
int num_suites;

/* HARDCODED LIST OF SUPPORTED CIPHER SUITES TAKEN FROM tls/s2n_cipher_suites.c */
static struct s2n_cipher_suite *s2n_all_cipher_suites[] = {
    &s2n_rsa_with_rc4_128_md5,                      /* 0x00,0x04 */
    &s2n_rsa_with_rc4_128_sha,                      /* 0x00,0x05 */
    &s2n_rsa_with_3des_ede_cbc_sha,                 /* 0x00,0x0A */
    &s2n_dhe_rsa_with_3des_ede_cbc_sha,             /* 0x00,0x16 */
    &s2n_rsa_with_aes_128_cbc_sha,                  /* 0x00,0x2F */
    &s2n_dhe_rsa_with_aes_128_cbc_sha,              /* 0x00,0x33 */
    &s2n_rsa_with_aes_256_cbc_sha,                  /* 0x00,0x35 */
    &s2n_dhe_rsa_with_aes_256_cbc_sha,              /* 0x00,0x39 */
    &s2n_rsa_with_aes_128_cbc_sha256,               /* 0x00,0x3C */
    &s2n_rsa_with_aes_256_cbc_sha256,               /* 0x00,0x3D */
    &s2n_dhe_rsa_with_aes_128_cbc_sha256,           /* 0x00,0x67 */
    &s2n_dhe_rsa_with_aes_256_cbc_sha256,           /* 0x00,0x6B */
    &s2n_rsa_with_aes_128_gcm_sha256,               /* 0x00,0x9C */
    &s2n_rsa_with_aes_256_gcm_sha384,               /* 0x00,0x9D */
    &s2n_dhe_rsa_with_aes_128_gcm_sha256,           /* 0x00,0x9E */
    &s2n_dhe_rsa_with_aes_256_gcm_sha384,           /* 0x00,0x9F */

    &s2n_tls13_aes_128_gcm_sha256,                  /* 0x13,0x01 */
    &s2n_tls13_aes_256_gcm_sha384,                  /* 0x13,0x02 */
    &s2n_tls13_chacha20_poly1305_sha256,            /* 0x13,0x03 */

    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,          /* 0xC0,0x09 */
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,          /* 0xC0,0x0A */
    &s2n_ecdhe_rsa_with_rc4_128_sha,                /* 0xC0,0x11 */
    &s2n_ecdhe_rsa_with_3des_ede_cbc_sha,           /* 0xC0,0x12 */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,            /* 0xC0,0x13 */
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,            /* 0xC0,0x14 */
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,       /* 0xC0,0x23 */
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,       /* 0xC0,0x24 */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,         /* 0xC0,0x27 */
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,         /* 0xC0,0x28 */
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,       /* 0xC0,0x2B */
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,       /* 0xC0,0x2C */
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,         /* 0xC0,0x2F */
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,         /* 0xC0,0x30 */
    &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,   /* 0xCC,0xA8 */
    &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256, /* 0xCC,0xA9 */
    &s2n_dhe_rsa_with_chacha20_poly1305_sha256,     /* 0xCC,0xAA */
    &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384,    /* 0xFF,0x04 */
    &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384,    /* 0xFF,0x08 */
};

static struct s2n_cipher_suite *s2n_all_fips_cipher_suites[] = {
    &s2n_rsa_with_3des_ede_cbc_sha,                /* 0x00,0x0A */
    &s2n_rsa_with_aes_128_cbc_sha,                 /* 0x00,0x2F */
    &s2n_rsa_with_aes_256_cbc_sha,                 /* 0x00,0x35 */
    &s2n_rsa_with_aes_128_cbc_sha256,              /* 0x00,0x3C */
    &s2n_rsa_with_aes_256_cbc_sha256,              /* 0x00,0x3D */
    &s2n_dhe_rsa_with_aes_128_cbc_sha256,          /* 0x00,0x67 */
    &s2n_dhe_rsa_with_aes_256_cbc_sha256,          /* 0x00,0x6B */
    &s2n_rsa_with_aes_128_gcm_sha256,              /* 0x00,0x9C */
    &s2n_rsa_with_aes_256_gcm_sha384,              /* 0x00,0x9D */
    &s2n_dhe_rsa_with_aes_128_gcm_sha256,          /* 0x00,0x9E */
    &s2n_dhe_rsa_with_aes_256_gcm_sha384,          /* 0x00,0x9F */
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,      /* 0xC0,0x23 */
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,      /* 0xC0,0x24 */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,        /* 0xC0,0x27 */
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,        /* 0xC0,0x28 */
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,      /* 0xC0,0x2B */
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,      /* 0xC0,0x2C */
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,        /* 0xC0,0x2F */
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,        /* 0xC0,0x30 */
};

static void s2n_fuzz_atexit()
{
    s2n_cleanup();
    free(cert_chain_pem);
    free(private_key_pem);
    free(dhparams_pem);
    s2n_config_free(config);
    s2n_cert_chain_and_key_free(chain_and_key);
}

int LLVMFuzzerInitialize(const uint8_t *buf, size_t len)
{
    notnull_check(s2n_all_cipher_suites);
    notnull_check(s2n_all_fips_cipher_suites);

#ifdef S2N_TEST_IN_FIPS_MODE
    S2N_TEST_ENTER_FIPS_MODE();
    test_suites = s2n_all_fips_cipher_suites;
    num_suites = s2n_array_len(s2n_all_fips_cipher_suites);
#else
    test_suites = s2n_all_cipher_suites;
    num_suites = s2n_array_len(s2n_all_cipher_suites);
#endif

    /* One time Diffie-Hellman negotiation to speed along fuzz tests*/
    GUARD(s2n_init());
    GUARD(atexit(s2n_fuzz_atexit));

    cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE);
    private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE);
    dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE);

    notnull_check(cert_chain_pem);
    notnull_check(private_key_pem);
    notnull_check(dhparams_pem);

    s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE);
    s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE);
    s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE);

    config = s2n_config_new();
    chain_and_key = s2n_cert_chain_and_key_new();

    notnull_check(config);
    notnull_check(chain_and_key);

    s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem);
    s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key);
    s2n_config_add_dhparams(config, dhparams_pem);

    cert = s2n_config_get_single_default_cert(config);
    notnull_check(cert);

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    for (int version = 0; version < s2n_array_len(TLS_VERSIONS); version++) {
        for (int cipher = 0; cipher < num_suites; cipher++) {

            /* Skip incompatible TLS 1.3 cipher suites */
            if (test_suites[cipher]->key_exchange_alg == NULL) {
                continue;
            }

            /* Setup */

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            notnull_check(server_conn);
            server_conn->server_protocol_version = TLS_VERSIONS[version];
            server_conn->secure.cipher_suite = test_suites[cipher];

            GUARD(s2n_stuffer_write_bytes(&server_conn->handshake.io, buf, len));
            server_conn->handshake_params.our_chain_and_key = cert;

            if (server_conn->secure.cipher_suite->key_exchange_alg->client_key_recv == s2n_ecdhe_client_key_recv || server_conn->secure.cipher_suite->key_exchange_alg->client_key_recv == s2n_hybrid_client_key_recv) {
                server_conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
                s2n_ecc_evp_generate_ephemeral_key(&server_conn->secure.server_ecc_evp_params);
            }

            if (server_conn->secure.cipher_suite->key_exchange_alg->client_key_recv == s2n_kem_client_key_recv || server_conn->secure.cipher_suite->key_exchange_alg->client_key_recv == s2n_hybrid_client_key_recv) {
                server_conn->secure.s2n_kem_keys.negotiated_kem = &s2n_sike_p503_r1;
            }

            /* Run Test
             * Do not use GUARD macro here since the connection memory hasn't been freed.
             */
            s2n_client_key_recv(server_conn);

            /* Cleanup */
            GUARD(s2n_connection_free(server_conn));
        }
    }
    return 0;
}
