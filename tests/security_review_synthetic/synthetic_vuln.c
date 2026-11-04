/*
 * SYNTHETIC SECURITY-REVIEW TEST INPUT - DO NOT MERGE, DO NOT BUILD.
 *
 * This file exists only to exercise the AI security reviewer on a throwaway
 * test pull request for the s2n-tls security-review integration. The two
 * functions below contain intentional, synthetic vulnerabilities so the
 * reviewer has something to flag. It is not referenced by any build target
 * and lives only on a disposable branch that is deleted after the test.
 */

#include <stdint.h>
#include <string.h>

/*
 * Synthetic (intentional): non-constant-time comparison of a secret MAC.
 * Comparing secret-dependent bytes with memcmp leaks timing information;
 * real code must use a constant-time comparison.
 */
int synthetic_verify_mac(const uint8_t *received, const uint8_t *expected, size_t len)
{
    return memcmp(received, expected, len) == 0;
}

/*
 * Synthetic (intentional): unbounded copy into a fixed-size stack buffer
 * using an attacker-controlled length (classic stack buffer overflow).
 */
void synthetic_copy_record(const uint8_t *input, size_t input_len)
{
    uint8_t buffer[16];
    memcpy(buffer, input, input_len);
    (void) buffer;
}
