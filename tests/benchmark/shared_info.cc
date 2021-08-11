#include "shared_info.h"

extern "C" {
#include "bin/common.h"

}

struct s2n_cipher_suite *all_suites[] = {
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_dhe_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_rc4_128_md5,
    &s2n_rsa_with_rc4_128_sha,
    &s2n_rsa_with_3des_ede_cbc_sha,
    &s2n_dhe_rsa_with_3des_ede_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_dhe_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_dhe_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha256,
    &s2n_dhe_rsa_with_aes_128_cbc_sha256,
    &s2n_dhe_rsa_with_aes_256_cbc_sha256,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_dhe_rsa_with_aes_128_gcm_sha256,

    &s2n_ecdhe_rsa_with_rc4_128_sha,
    &s2n_ecdhe_rsa_with_3des_ede_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,

    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,


    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,

    &s2n_dhe_rsa_with_chacha20_poly1305_sha256,
    &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384,

    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
};

uint8_t ticket_key_name[16] = "2016.07.26.15\0";

uint8_t default_ticket_key[32] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc,
                                         0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b,
                                         0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
                                         0xb3, 0xe5 };

int DEBUG_PRINT = 0;
int WARMUP_ITERS = 1;
unsigned int ITERATIONS = 50;

int benchmark_negotiate(struct s2n_connection *conn, int fd, benchmark::State& state, bool warmup) {
    s2n_blocked_status blocked;
    int s2n_ret;
    if(!warmup) {
        state.ResumeTiming();
    }
    benchmark::DoNotOptimize(s2n_ret = s2n_negotiate(conn, &blocked)); //forces the result to be stored in either memory or a register.
    if(!warmup) {
        state.PauseTiming();
    }
    benchmark::ClobberMemory(); //forces the compiler to perform all pending writes to global memory

    if (s2n_ret != S2N_SUCCESS) {
        if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Failed to negotiate: '%s'. %s\n",
                    s2n_strerror(s2n_errno, "EN"),
                    s2n_strerror_debug(s2n_errno, "EN"));
            fprintf(stderr, "Alert: %d\n",
                    s2n_connection_get_alert(conn));
            printf("Client errno: %s\n", strerror(errno));
            S2N_ERROR_PRESERVE_ERRNO();
        }

        if (wait_for_event(fd, blocked) != S2N_SUCCESS) {
            S2N_ERROR_PRESERVE_ERRNO();
        }

        state.SkipWithError("Negotiate Failed\n");
    }

    if(DEBUG_PRINT) {
        print_connection_info(conn);
    }

    return 0;
}