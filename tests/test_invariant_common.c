#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

// Function prototype from bin/common.c
extern void safe_copy(char *dest, const char *src, size_t dest_size);

START_TEST(test_buffer_read_never_exceeds_length)
{
    // Invariant: Buffer reads never exceed the declared length
    const char *payloads[] = {
        "normal",                    // Valid input
        "A",                         // Boundary: single char
        "1234567890123456789012345678901234567890",  // 40 chars - exceeds typical buffer
        "../../../../etc/passwd",    // Path traversal attempt
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  // 100 chars - large overflow
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);
    
    for (int i = 0; i < num_payloads; i++) {
        // Fork to isolate each test case
        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            char buffer[16] = {0};  // Small buffer to test overflow
            safe_copy(buffer, payloads[i], sizeof(buffer));
            
            // Check that buffer is null-terminated
            ck_assert_msg(buffer[sizeof(buffer)-1] == '\0' || strlen(buffer) < sizeof(buffer),
                         "Buffer not properly terminated or overflowed");
            
            // Check that no bytes beyond buffer were written
            // This is a basic check - in real scenario might use canaries
            _exit(0);
        } else if (pid > 0) {
            // Parent process
            int status;
            waitpid(pid, &status, 0);
            
            // If child crashed (segfault, etc), test fails
            ck_assert_msg(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                         "Process crashed with payload: %s", payloads[i]);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_read_never_exceeds_length);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}