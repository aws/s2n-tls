#include <sys/param.h>
#include <cpuid.h>

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_cpu.h"

/* See https://en.wikipedia.org/wiki/CPUID */
#define RDRAND_FLAG     0x40000000
#define AESNI_FLAG      0x02000000

int s2n_cpu_supports_aesni()
{
#if defined(__x86_64__)||defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }

    if (ecx & AESNI_FLAG) {
        return 1;
    }
#endif

    return 0;
}

int s2n_cpu_supports_rdrand()
{
#if defined(__x86_64__)||defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }

    if (ecx & RDRAND_FLAG) {
        return 1;
    }
#endif

    return 0;
}

int s2n_cpu_get_rdrand_data(struct s2n_blob *out)
{

#if defined(__x86_64__)||defined(__i386__)
    int space_remaining = 0;
    struct s2n_stuffer stuffer;
    union {
        uint64_t u64;
        uint8_t  u8[8];
    } output;

    GUARD(s2n_stuffer_init(&stuffer, out));

    while((space_remaining = s2n_stuffer_space_remaining(&stuffer))) {
        int success = 0;

        for (int tries = 0; tries < 10; tries++) {

            __asm__ __volatile__(
             ".byte 0x48;\n"
             ".byte 0x0f;\n"
             ".byte 0xc7;\n"
             ".byte 0xf0;\n"
             "adcl $0x00, %%ebx;\n"
             :"=b"(success), "=a"(output.u64) 
             :"b"(0)
             :"cc"
                                );

            if (success) {
                break;
            }
        }

        if (!success) {
            return -1;
        }

        int data_to_fill = MIN(sizeof(output), space_remaining);

        GUARD(s2n_stuffer_write_bytes(&stuffer, output.u8, data_to_fill));
    }

    return 0;
#else 
    return -1;
#endif
}
