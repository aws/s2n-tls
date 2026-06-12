#ifndef BSD_SYS_CPUSET_H
#define BSD_SYS_CPUSET_H

/* clang-format off */
#if defined(_MSC_VER) || defined(__MINGW32__)
#include <stddef.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#define CPU_SETSIZE 64

#define _CPU_SET_ULONG_BITS (sizeof(unsigned long) * 8)

/**
 * @brief CPU set structure
 */
typedef struct {
  unsigned long __bits[CPU_SETSIZE / 32];
} cpuset_t;

/**
 * @brief Initialize CPU set to zero
 * @param set Pointer to cpuset_t
 */
#define CPU_ZERO(set)                                                          \
  do {                                                                         \
    size_t _i;                                                                 \
    for (_i = 0; _i < sizeof((set)->__bits) / sizeof(unsigned long); _i++)     \
      (set)->__bits[_i] = 0;                                                   \
  } while (0)

/**
 * @brief Set a CPU in the set
 * @param cpu CPU index
 * @param set Pointer to cpuset_t
 */
#define CPU_SET(cpu, set)                                                      \
  do {                                                                         \
    if ((cpu) < CPU_SETSIZE)                                                   \
      (set)->__bits[(cpu) / _CPU_SET_ULONG_BITS] |=                            \
          (1UL << ((cpu) % _CPU_SET_ULONG_BITS));                              \
  } while (0)

/**
 * @brief Clear a CPU from the set
 * @param cpu CPU index
 * @param set Pointer to cpuset_t
 */
#define CPU_CLR(cpu, set)                                                      \
  do {                                                                         \
    if ((cpu) < CPU_SETSIZE)                                                   \
      (set)->__bits[(cpu) / _CPU_SET_ULONG_BITS] &=                            \
          ~(1UL << ((cpu) % _CPU_SET_ULONG_BITS));                             \
  } while (0)

/**
 * @brief Check if a CPU is in the set
 * @param cpu CPU index
 * @param set Pointer to cpuset_t
 * @return 1 if set, 0 otherwise
 */
#define CPU_ISSET(cpu, set)                                                    \
  (((cpu) < CPU_SETSIZE) ? (((set)->__bits[(cpu) / _CPU_SET_ULONG_BITS] &      \
                             (1UL << ((cpu) % _CPU_SET_ULONG_BITS))) != 0)     \
                         : 0)

typedef int cpulevel_t;
typedef int cpuwhich_t;
typedef int id_t;

#define CPU_LEVEL_ROOT 1
#define CPU_LEVEL_CPUSET 2
#define CPU_LEVEL_WHICH 3

#define CPU_WHICH_TID 1
#define CPU_WHICH_PID 2
#define CPU_WHICH_CPUSET 3
#define CPU_WHICH_IRQ 4
#define CPU_WHICH_JAIL 5
#define CPU_WHICH_DOMAIN 6
#define CPU_WHICH_INTRHANDLER 7
#define CPU_WHICH_ITHREAD 8

/**
 * @brief Get CPU affinity mask
 * @param level The cpulevel_t
 * @param which The cpuwhich_t
 * @param id The id_t
 * @param setsize The size of the mask
 * @param mask Pointer to cpuset_t
 * @return 0 on success, -1 on failure
 */
int cpuset_getaffinity(cpulevel_t level, cpuwhich_t which, id_t id,
                       size_t setsize, cpuset_t *mask);

/**
 * @brief Set CPU affinity mask
 * @param level The cpulevel_t
 * @param which The cpuwhich_t
 * @param id The id_t
 * @param setsize The size of the mask
 * @param mask Pointer to cpuset_t
 * @return 0 on success, -1 on failure
 */
int cpuset_setaffinity(cpulevel_t level, cpuwhich_t which, id_t id,
                       size_t setsize, const cpuset_t *mask);

#endif /* _MSC_VER || __MINGW32__ */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* BSD_SYS_CPUSET_H */
