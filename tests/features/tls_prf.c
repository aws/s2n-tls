
#include <openssl/base.h>
#include <openssl/digest.h>

#define TEST_BUFFER_SIZE 64

/* BoringSSL and AWSLC define the CRYPTO_tls1_prf API in a private header. This function is
 * forward-declared to make it accessible.
 */
int CRYPTO_tls1_prf(const EVP_MD *digest,
        uint8_t *out, size_t out_len,
        const uint8_t *secret, size_t secret_len,
        const char *label, size_t label_len,
        const uint8_t *seed1, size_t seed1_len,
        const uint8_t *seed2, size_t seed2_len);

int main()
{
    const EVP_MD *digest = EVP_md5_sha1();

    uint8_t out[TEST_BUFFER_SIZE] = { 0 };
    uint8_t secret[TEST_BUFFER_SIZE] = { 0 };
    const char label[TEST_BUFFER_SIZE] = { 0 };
    uint8_t seed1[TEST_BUFFER_SIZE] = { 0 };
    uint8_t seed2[TEST_BUFFER_SIZE] = { 0 };

    if (!CRYPTO_tls1_prf(digest, out, TEST_BUFFER_SIZE, secret, TEST_BUFFER_SIZE, label,
                TEST_BUFFER_SIZE, seed1, TEST_BUFFER_SIZE, seed2, TEST_BUFFER_SIZE)) {
        return 1;
    }

    return 0;
}
