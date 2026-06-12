/* posix-sched.h - Strict C89 Header */
#ifndef POSIX_SCHED_H
#define POSIX_SCHED_H

/**
 * @file posix-sched.h
 * @brief POSIX sched.h implementation for MSVC
 *
 * This header maps thread scheduling and CPU affinity functions
 * using Windows process APIs.
 */

#if defined(_MSC_VER) || defined(_WIN32) || defined(__MSDOS__) ||              \
    defined(__WATCOMC__)
/* clang-format off */
#include <stddef.h> /* size_t */
#else
#include <sched.h>
#endif
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER) || defined(_WIN32) || defined(__MSDOS__) ||              \
    defined(__WATCOMC__)

#define CPU_SETSIZE 64

/**
 * @brief Structure for representing a CPU affinity mask.
 */
#if defined(__GNUC__)
__extension__ typedef unsigned long long mask_bit_type;
#elif defined(_MSC_VER) || defined(__WATCOMC__)
typedef unsigned __int64 mask_bit_type;
#else
typedef unsigned long long mask_bit_type;
#endif

typedef struct cpu_set {
#if defined(__GNUC__)
  __extension__ unsigned long long bits;
#elif defined(_MSC_VER) || defined(__WATCOMC__)
  unsigned __int64 bits;
#else
  unsigned long long bits;
#endif
} cpu_set_t;

/**
 * @brief Clears set, so that it contains no CPUs.
 */
#define CPU_ZERO(set)                                                          \
  do {                                                                         \
    (set)->bits = 0;                                                           \
  } while (0)

/**
 * @brief Add CPU cpu to set.
 */
#define CPU_SET(cpu, set)                                                      \
  do {                                                                         \
    if ((cpu) < 64)                                                            \
      (set)->bits |= (((mask_bit_type)1) << (cpu));                            \
  } while (0)

/**
 * @brief Remove CPU cpu from set.
 */
#define CPU_CLR(cpu, set)                                                      \
  do {                                                                         \
    if ((cpu) < 64)                                                            \
      (set)->bits &= ~(((mask_bit_type)1) << (cpu));                           \
  } while (0)

/**
 * @brief Test to see if CPU cpu is a member of set.
 */
#define CPU_ISSET(cpu, set)                                                    \
  (((cpu) < 64) ? (((set)->bits & (((mask_bit_type)1) << (cpu))) != 0) : 0)

/**
 * @brief Relinquish the CPU.
 *
 * Mapped to Windows SwitchToThread() API.
 *
 * @return 0 on success.
 */
int posix_sched_yield(void);

/**
 * @brief Set a process's CPU affinity mask.
 *
 * @param pid Process ID. (0 means current process).
 * @param cpusetsize Size of mask struct in bytes.
 * @param mask Pointer to the new cpu_set_t mask.
 * @return 0 on success, -1 on error.
 */
int posix_sched_setaffinity(int pid, size_t cpusetsize, const cpu_set_t *mask);

/**
 * @brief Get a process's CPU affinity mask.
 *
 * @param pid Process ID. (0 means current process).
 * @param cpusetsize Size of mask struct in bytes.
 * @param mask Pointer to the cpu_set_t mask to be populated.
 * @return 0 on success, -1 on error.
 */
int posix_sched_getaffinity(int pid, size_t cpusetsize, cpu_set_t *mask);

#ifndef sched_yield
#define sched_yield posix_sched_yield
#endif
#ifndef sched_setaffinity
#define sched_setaffinity posix_sched_setaffinity
#endif
#ifndef sched_getaffinity
#define sched_getaffinity posix_sched_getaffinity
#endif

#endif /* defined(_MSC_VER) || defined(_WIN32) */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_SCHED_H */
