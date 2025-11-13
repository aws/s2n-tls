#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Hmmmmmm there's something wrong with the code snippet below...
 * 
 * When this code runs it fails and an error message is printed out!
 * Can you help figure out why this code is broken by using the
 * power of the GNU Debugger? 
 * 
 * Step 1: Compile this code with debugging symbols
 * Step 2: Run the executable and confirm that it fails
 * Step 3: Use the gdb tool to step through the code to discover the issue
 * 
 * Success criteria: You can explain to @madelea where and why this code snippet
 * is failing!
 */

static pthread_key_t my_key;

int main(int argc, char **argv)
{
    for (size_t i = 0; i <= 3000; i++) {
        int result = 0;
        result = pthread_key_create(&my_key, NULL);
        if (result != 0) {
            printf("FAILED: pthread_key_create call failed :(\n");
            exit(1);
        };
    }
    return 0;
}