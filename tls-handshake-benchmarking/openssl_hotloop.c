/*
 * openssl_hotloop.c — TLS 1.3 full-handshake hot loop for OpenSSL/BoringSSL,
 * mirroring the harness's --hotloop mode so its perf captures can be compared
 * operation-level against s2n-tls/rustls via analyze_selftime.py.
 *
 * Config parity with the Rust harness (see README "Key configuration decisions"):
 *   - TLS 1.3 only
 *   - cipher suite pinned to TLS_AES_128_GCM_SHA256
 *   - groups X25519MLKEM768 first (hybrid PQ), x25519 classical fallback
 *   - full handshakes: fresh SSL objects each iteration, tickets disabled,
 *     no session reuse
 *   - client validates the server chain against the CA (no hostname check,
 *     matching the harness's accept-all host callback)
 *   - in-process client+server over memory BIOs (no sockets)
 *
 * Usage:
 *   ./openssl_hotloop <cert_type> <chain.pem> <key.pem> <ca.pem> [secs]
 *
 * Cert PEMs should come from the harness so the chain shape matches:
 *   ./target/release/tls-handshake-benchmarking --dump-certs rsa2048 /tmp/certs
 *
 * Build:
 *   gcc -O2 -g openssl_hotloop.c -o openssl_hotloop -lssl -lcrypto
 *
 * Output: the same machine-readable mean as the Rust harness —
 *   [hotloop] impl=openssl cert=<cert_type> handshakes=N elapsed_s=S mean_us=M
 * plus a sidecar file hotloop_mean_openssl_<cert_type>.txt
 */
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void die(const char *msg)
{
    fprintf(stderr, "FATAL: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}

/* Drive both ends until the handshake completes on each. The BIO pair is
 * directly linked, so we just alternate SSL_do_handshake calls; WANT_READ /
 * WANT_WRITE mean "the peer needs to run", not an error. */
static void do_handshake_pair(SSL *client, SSL *server)
{
    int client_done = 0, server_done = 0;
    /* Bounded loop: a TLS 1.3 handshake needs only a few alternations.
     * 100 rounds without completion means something is genuinely wrong. */
    for (int i = 0; i < 100 && !(client_done && server_done); i++) {
        if (!client_done) {
            int r = SSL_do_handshake(client);
            if (r == 1) {
                client_done = 1;
            } else {
                int err = SSL_get_error(client, r);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                    die("client handshake error");
            }
        }
        if (!server_done) {
            int r = SSL_do_handshake(server);
            if (r == 1) {
                server_done = 1;
            } else {
                int err = SSL_get_error(server, r);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                    die("server handshake error");
            }
        }
    }
    if (!(client_done && server_done))
        die("handshake did not complete within the alternation bound");
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr,
                "usage: %s <cert_type> <chain.pem> <key.pem> <ca.pem> [secs]\n",
                argv[0]);
        return 1;
    }
    const char *cert_type = argv[1];
    const char *chain_pem = argv[2];
    const char *key_pem = argv[3];
    const char *ca_pem = argv[4];
    long secs = (argc > 5) ? atol(argv[5]) : 20;

    /* ---- server context ---- */
    SSL_CTX *sctx = SSL_CTX_new(TLS_server_method());
    if (!sctx) die("SSL_CTX_new server");
    if (SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION) != 1) die("server min proto");
    if (SSL_CTX_set_ciphersuites(sctx, "TLS_AES_128_GCM_SHA256") != 1) die("server ciphersuites");
    if (SSL_CTX_set1_groups_list(sctx, "X25519MLKEM768:x25519") != 1) die("server groups");
    if (SSL_CTX_use_certificate_chain_file(sctx, chain_pem) != 1) die("server chain");
    if (SSL_CTX_use_PrivateKey_file(sctx, key_pem, SSL_FILETYPE_PEM) != 1) die("server key");
    /* Full handshakes only: no session tickets, no cache (parity: rustls
     * resumption disabled, s2n has no ticket key configured). */
    SSL_CTX_set_num_tickets(sctx, 0);
    SSL_CTX_set_session_cache_mode(sctx, SSL_SESS_CACHE_OFF);

    /* ---- client context ---- */
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method());
    if (!cctx) die("SSL_CTX_new client");
    if (SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION) != 1) die("client min proto");
    if (SSL_CTX_set_ciphersuites(cctx, "TLS_AES_128_GCM_SHA256") != 1) die("client ciphersuites");
    if (SSL_CTX_set1_groups_list(cctx, "X25519MLKEM768:x25519") != 1) die("client groups");
    if (SSL_CTX_load_verify_locations(cctx, ca_pem, NULL) != 1) die("client CA");
    /* Chain validation ON, hostname check off (harness parity). */
    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_OFF);

    const int warmup = 200;
    long count = 0;
    double loop_start = 0;
    double deadline = now_s() + 1e18; /* set after warmup */

    for (long i = 0;; i++) {
        if (i == warmup) {
            loop_start = now_s();
            deadline = loop_start + (double) secs;
        }
        if (i >= warmup && now_s() >= deadline)
            break;

        SSL *server = SSL_new(sctx);
        SSL *client = SSL_new(cctx);
        if (!server || !client) die("SSL_new");

        BIO *cbio = NULL, *sbio = NULL;
        if (BIO_new_bio_pair(&cbio, 0, &sbio, 0) != 1) die("BIO_new_bio_pair");
        SSL_set_bio(client, cbio, cbio); /* SSL takes ownership */
        SSL_set_bio(server, sbio, sbio);
        SSL_set_connect_state(client);
        SSL_set_accept_state(server);

        do_handshake_pair(client, server);

        /* One-time config-parity report: confirm what was actually negotiated
         * (suite and group must match the s2n/rustls runs to be comparable). */
        if (i == 0) {
            const char *group = SSL_get0_group_name(client);
            fprintf(stderr, "[config] version=%s cipher=%s group=%s\n",
                    SSL_get_version(client),
                    SSL_get_cipher_name(client),
                    group ? group : "?");
        }

        if (i >= warmup)
            count++;
        SSL_free(client);
        SSL_free(server);
    }

    double elapsed = now_s() - loop_start;
    double mean_us = elapsed * 1e6 / (double) count;
    fprintf(stderr,
            "[hotloop] impl=openssl cert=%s handshakes=%ld elapsed_s=%.3f mean_us=%.3f\n",
            cert_type, count, elapsed, mean_us);

    char sidecar[256];
    snprintf(sidecar, sizeof(sidecar), "hotloop_mean_openssl_%s.txt", cert_type);
    FILE *f = fopen(sidecar, "w");
    if (f) {
        fprintf(f, "%.3f", mean_us);
        fclose(f);
    }

    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return 0;
}
