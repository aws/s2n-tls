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

/* Target Functions: s2n_certificate_extensions_parse
                     s2n_recv_server_sct_list s2n_server_certificate_status_recv
                     s2n_x509_validator_validate_cert_stapled_ocsp_response */

#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/extensions/s2n_extension_list.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls13.h"

static uint32_t write_pem_file_to_stuffer_as_chain(struct s2n_stuffer *chain_out_stuffer, const char *pem_data)
{
    struct s2n_stuffer chain_in_stuffer = {0}, cert_stuffer = {0};
    s2n_stuffer_alloc_ro_from_string(&chain_in_stuffer, pem_data);
    s2n_stuffer_growable_alloc(&cert_stuffer, 4096);
    s2n_stuffer_growable_alloc(chain_out_stuffer, 4096);

    uint32_t chain_size = 0;
    do {
        s2n_stuffer_certificate_from_pem(&chain_in_stuffer, &cert_stuffer);
        uint32_t cert_len = s2n_stuffer_data_available(&cert_stuffer);
        uint8_t *raw_cert_data = s2n_stuffer_raw_read(&cert_stuffer, cert_len);

        if (cert_len) {
            struct s2n_blob cert_data = {.data = raw_cert_data, .size = cert_len};
            chain_size += cert_data.size + 3;
            s2n_stuffer_write_uint24(chain_out_stuffer, cert_data.size);
            s2n_stuffer_write(chain_out_stuffer, &cert_data);
        }
    } while (s2n_stuffer_data_available(&chain_in_stuffer));

    s2n_stuffer_free(&cert_stuffer);
    s2n_stuffer_free(&chain_in_stuffer);
    return chain_size;
}

struct host_verify_data {
    const char *name;
    uint8_t found_name;
    uint8_t callback_invoked;
};

static uint8_t verify_host_accept_everything(const char *host_name, size_t host_name_len, void *data)
{
    struct host_verify_data *verify_data = (struct host_verify_data *) data;
    verify_data->callback_invoked = 1;
    return 1;
}

/* This test is for TLS versions 1.3 and up only */
static const uint8_t TLS_VERSIONS[] = {S2N_TLS13};

int s2n_fuzz_init(int *argc, char **argv[])
{
    GUARD(s2n_enable_tls13());
    return S2N_SUCCESS;
}

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
    /* We need at least one byte of input to set parameters */
    S2N_FUZZ_ENSURE_MIN_LEN(len, 1);

    /* Setup */
    struct s2n_stuffer fuzz_stuffer = {0};
    GUARD(s2n_stuffer_alloc(&fuzz_stuffer, len));
    GUARD(s2n_stuffer_write_bytes(&fuzz_stuffer, buf, len));

    struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
    notnull_check(client_conn);

    /* Pull a byte off the libfuzzer input and use it to set parameters */
    uint8_t randval = 0;
    GUARD(s2n_stuffer_read_uint8(&fuzz_stuffer, &randval));
    client_conn->x509_validator.skip_cert_validation = (randval >> 7) % 2;

    /* Set connection to TLS 1.2 to temporary work around cert validation setup */
    client_conn->actual_protocol_version = S2N_TLS12;

    /* Set cert chain and trust store for verification of OCSP response */
    if ((randval >> 6) % 2 && OPENSSL_VERSION_NUMBER >= 0x10101000L) {
        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        GUARD(s2n_connection_set_verify_host_callback(client_conn, verify_host_accept_everything, &verify_data));
        char cert_chain[S2N_MAX_TEST_PEM_SIZE];
        GUARD(s2n_read_test_pem(S2N_OCSP_CA_CERT, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        GUARD(s2n_x509_trust_store_add_pem(client_conn->x509_validator.trust_store, cert_chain));
        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        GUARD(s2n_read_test_pem(S2N_OCSP_SERVER_CERT, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer;
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);
        struct s2n_pkey public_key_out;
        GUARD(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;

        GUARD(s2n_x509_validator_validate_cert_chain(&client_conn->x509_validator, client_conn, chain_data, chain_len, &pkey_type, &public_key_out));
        GUARD(s2n_stuffer_free(&chain_stuffer));
        GUARD(s2n_pkey_free(&public_key_out));
    }

    client_conn->actual_protocol_version = TLS_VERSIONS[(randval & 0x07) % s2n_array_len(TLS_VERSIONS)];
    client_conn->client_protocol_version = TLS_VERSIONS[((randval >> 3) & 0x07) % s2n_array_len(TLS_VERSIONS)];

    /* Run Test
     * Do not use GUARD macro here since the connection memory hasn't been freed.
     */
    s2n_extension_list_recv(S2N_EXTENSION_LIST_CERTIFICATE, client_conn, &fuzz_stuffer);

    /* Cleanup */
    GUARD(s2n_connection_free(client_conn));
    GUARD(s2n_stuffer_free(&fuzz_stuffer));

    return S2N_SUCCESS;
}

S2N_FUZZ_TARGET(s2n_fuzz_init, s2n_fuzz_test, NULL)
