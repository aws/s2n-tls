#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

#include "testlib/s2n_testlib.h"
#include "tests/s2n_test.h"
#include "utils/s2n_safety.h"

#define SERVER_CHAIN       "/home/ubuntu/workspace/s2n-tls/tests/pems/permutations/rsae_pkcs_2048_sha256/server-chain.pem"
#define SERVER_KEY         "/home/ubuntu/workspace/s2n-tls/tests/pems/permutations/rsae_pkcs_2048_sha256/server-key.pem"
#define OPENSSL_1_0_2_MASK 0x10002000L

#define EXPECT_OSSL_SUCCESS(e1) EXPECT_TRUE(e1 > -1)

struct s2n_client_hello_version_detector {
    uint8_t invoked;
};

int sslv2_assertion_cb(struct s2n_connection *conn, void *ctx)
{
    EXPECT_EQUAL(s2n_connection_get_client_hello_version(conn), S2N_SSLv2);

    struct s2n_client_hello_version_detector *detector = ctx;
    detector->invoked += 1;

    return 0;
}

/* s2n-tls io recv callback that operates on an OpenSSL BIO. */
int s2n_bio_read(void *io_context, uint8_t *buf, uint32_t len)
{
    int bytes_read = BIO_read(io_context, buf, len);
    if (bytes_read == -1) {
        errno = EWOULDBLOCK;
    }
    return bytes_read;
}

/* s2n-tls io send callback that operates on an OpenSSL BIO. */
int s2n_bio_write(void *io_context, const uint8_t *buf, uint32_t len)
{
    return BIO_write(io_context, buf, len);
}


S2N_RESULT s2n_negotiate_s2n_and_ossl(SSL *client, struct s2n_connection *server)
{
    bool server_done = false, client_done = false;
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    do {
        int ret = SSL_do_handshake(client);
        if (ret == 1) {
            client_done = true;
        } else {
            /* if error not caused by blocked io, fail */
            int err = SSL_get_error(client, ret);
            RESULT_ENSURE(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE, S2N_ERR_IO);
        }

        server_done = (s2n_negotiate(server, &blocked) >= S2N_SUCCESS);
        if (!server_done) {
            /* if error not caused by blocked io, fail */
            RESULT_ENSURE_EQ(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
        }

    } while (!client_done || !server_done);

    return S2N_RESULT_OK;
}

int main()
{
    // Assert that we are pulling in the correct openssl header.
    EXPECT_EQUAL(OPENSSL_VERSION_NUMBER & OPENSSL_1_0_2_MASK, OPENSSL_1_0_2_MASK);

    EXPECT_OSSL_SUCCESS(SSL_library_init());
    SSL_load_error_strings();
    EXPECT_SUCCESS(s2n_init());

    /* s2n-tls client w/ openssl server */
    {
        /* s2n-tls server config */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                SERVER_CHAIN, SERVER_KEY));

        struct s2n_client_hello_version_detector client_hello_detector = { 0 };

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "PQ-TLS-1-2-2023-12-13"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_wipe_trust_store(config));
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, sslv2_assertion_cb, &client_hello_detector));

        /* OpenSSL client config */
        SSL_CTX *client_ctx = SSL_CTX_new(SSLv23_client_method());
        EXPECT_NOT_NULL(client_ctx);
        /* SSLv2 is disabled by default, so we must explicitly clear the setting.
         * https://github.com/openssl/openssl/blob/master/CHANGES.md#changes-between-102f-and-102g-1-mar-2016
         */
        EXPECT_OSSL_SUCCESS(SSL_CTX_clear_options(client_ctx, SSL_OP_NO_SSLv2));
        /* Explicitly enable SSLv2 cipher suites to force OpenSSL to send an SSLv2
         * ClientHello. Also enable modern cipher suites to allow us to actually
         * negotiate TLS 1.2.
         */
        EXPECT_OSSL_SUCCESS(SSL_CTX_set_cipher_list(client_ctx, "SSLv2:RSA"));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        SSL *client_conn = SSL_new(client_ctx);
        EXPECT_NOT_NULL(client_conn);

        /* setup io for the connections */
        BIO *server_to_client = BIO_new(BIO_s_mem());
        BIO *client_to_server = BIO_new(BIO_s_mem());
        EXPECT_NOT_NULL(server_to_client);
        EXPECT_NOT_NULL(client_to_server);

        EXPECT_SUCCESS(s2n_connection_set_recv_cb(server_conn, s2n_bio_read));
        EXPECT_SUCCESS(s2n_connection_set_recv_ctx(server_conn, client_to_server));
        EXPECT_SUCCESS(s2n_connection_set_send_cb(server_conn, s2n_bio_write));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(server_conn, server_to_client));

        SSL_set_bio(client_conn, server_to_client, client_to_server);
        SSL_set_connect_state(client_conn);

        EXPECT_OK(s2n_negotiate_s2n_and_ossl(client_conn, server_conn));

        EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server_conn), S2N_TLS12);
        EXPECT_EQUAL(client_hello_detector.invoked, 1);

        // Cleanup
        SSL_free(client_conn);
        SSL_CTX_free(client_ctx);
    }

    return 0;
}
