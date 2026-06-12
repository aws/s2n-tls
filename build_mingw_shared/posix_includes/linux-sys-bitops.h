/* linux-sys-bitops/include/linux-sys-bitops.h - Strict C89 Implementation */
#ifndef LINUX_SYS_BITOPS_H
#define LINUX_SYS_BITOPS_H

#if defined(_MSC_VER)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
/* clang-format off */
#include <winsock2.h>
#include <ws2tcpip.h>

#include <intrin.h>
/* clang-format on */

#pragma intrinsic(_BitScanForward)
#pragma intrinsic(_BitScanReverse)
#if defined(_WIN64)
#pragma intrinsic(_BitScanForward64)
#pragma intrinsic(_BitScanReverse64)
#endif
#pragma intrinsic(_bittest)
#pragma intrinsic(_bittestandset)
#pragma intrinsic(_bittestandreset)
#pragma intrinsic(_bittestandcomplement)

#ifdef __cplusplus
extern "C" {
#endif

#define LINUX_SYS_BITOPS_INLINE static __inline

LINUX_SYS_BITOPS_INLINE int posix_ffs(int x) {
  unsigned long index;
  if (!x)
    return 0;
  if (_BitScanForward(&index, (unsigned long)x))
    return (int)index + 1;
  return 0;
}

LINUX_SYS_BITOPS_INLINE int posix_fls(int x) {
  unsigned long index;
  if (!x)
    return 0;
  if (_BitScanReverse(&index, (unsigned long)x))
    return (int)index + 1;
  return 0;
}

LINUX_SYS_BITOPS_INLINE int posix_fls64(unsigned __int64 x) {
  unsigned long index;
  if (!x)
    return 0;
#if defined(_WIN64)
  if (_BitScanReverse64(&index, x))
    return (int)index + 1;
#else
  if ((unsigned long)(x >> 32)) {
    if (_BitScanReverse(&index, (unsigned long)(x >> 32)))
      return (int)index + 33;
  } else {
    if (_BitScanReverse(&index, (unsigned long)x))
      return (int)index + 1;
  }
#endif
  return 0;
}

LINUX_SYS_BITOPS_INLINE unsigned long posix___ffs(unsigned long word) {
  unsigned long index;
  _BitScanForward(&index, word);
  return index;
}

LINUX_SYS_BITOPS_INLINE unsigned long posix_ffz(unsigned long word) {
  unsigned long index;
  _BitScanForward(&index, ~word);
  return index;
}

LINUX_SYS_BITOPS_INLINE void posix_set_bit(int nr,
                                           volatile unsigned long *addr) {
  volatile long *p = (volatile long *)addr + (nr / 32);
  long mask = 1L << (nr % 32);
  long old, prev;
  do {
    prev = *p;
    old = InterlockedCompareExchange(p, prev | mask, prev);
  } while (old != prev);
}

LINUX_SYS_BITOPS_INLINE void posix_clear_bit(int nr,
                                             volatile unsigned long *addr) {
  volatile long *p = (volatile long *)addr + (nr / 32);
  long mask = ~(1L << (nr % 32));
  long old, prev;
  do {
    prev = *p;
    old = InterlockedCompareExchange(p, prev & mask, prev);
  } while (old != prev);
}

LINUX_SYS_BITOPS_INLINE void posix_change_bit(int nr,
                                              volatile unsigned long *addr) {
  volatile long *p = (volatile long *)addr + (nr / 32);
  long mask = 1L << (nr % 32);
  long old, prev;
  do {
    prev = *p;
    old = InterlockedCompareExchange(p, prev ^ mask, prev);
  } while (old != prev);
}

LINUX_SYS_BITOPS_INLINE int
posix_test_and_set_bit(int nr, volatile unsigned long *addr) {
  volatile long *p = (volatile long *)addr + (nr / 32);
  long mask = 1L << (nr % 32);
  long old, prev;
  do {
    prev = *p;
    old = InterlockedCompareExchange(p, prev | mask, prev);
  } while (old != prev);
  return (old & mask) != 0;
}

LINUX_SYS_BITOPS_INLINE int
posix_test_and_clear_bit(int nr, volatile unsigned long *addr) {
  volatile long *p = (volatile long *)addr + (nr / 32);
  long mask = ~(1L << (nr % 32));
  long bit_mask = 1L << (nr % 32);
  long old, prev;
  do {
    prev = *p;
    old = InterlockedCompareExchange(p, prev & mask, prev);
  } while (old != prev);
  return (old & bit_mask) != 0;
}

LINUX_SYS_BITOPS_INLINE int
posix_test_and_change_bit(int nr, volatile unsigned long *addr) {
  volatile long *p = (volatile long *)addr + (nr / 32);
  long mask = 1L << (nr % 32);
  long old, prev;
  do {
    prev = *p;
    old = InterlockedCompareExchange(p, prev ^ mask, prev);
  } while (old != prev);
  return (old & mask) != 0;
}

LINUX_SYS_BITOPS_INLINE void posix___set_bit(int nr,
                                             volatile unsigned long *addr) {
  _bittestandset((long *)addr, nr);
}

LINUX_SYS_BITOPS_INLINE void posix___clear_bit(int nr,
                                               volatile unsigned long *addr) {
  _bittestandreset((long *)addr, nr);
}

LINUX_SYS_BITOPS_INLINE void posix___change_bit(int nr,
                                                volatile unsigned long *addr) {
  _bittestandcomplement((long *)addr, nr);
}

LINUX_SYS_BITOPS_INLINE int
posix___test_and_set_bit(int nr, volatile unsigned long *addr) {
  return _bittestandset((long *)addr, nr) != 0;
}

LINUX_SYS_BITOPS_INLINE int
posix___test_and_clear_bit(int nr, volatile unsigned long *addr) {
  return _bittestandreset((long *)addr, nr) != 0;
}

LINUX_SYS_BITOPS_INLINE int
posix___test_and_change_bit(int nr, volatile unsigned long *addr) {
  return _bittestandcomplement((long *)addr, nr) != 0;
}

LINUX_SYS_BITOPS_INLINE int posix_test_bit(int nr,
                                           const volatile unsigned long *addr) {
  return _bittest((const long *)addr, nr) != 0;
}

#else /* !_MSC_VER */

#if defined(__GNUC__) || defined(__clang__)
#define LINUX_SYS_BITOPS_INLINE static __inline__
#elif defined(__WATCOMC__)
#define LINUX_SYS_BITOPS_INLINE static __inline
#else
#define LINUX_SYS_BITOPS_INLINE static
#endif

LINUX_SYS_BITOPS_INLINE int posix_ffs(int x) {
#if defined(__GNUC__) || defined(__clang__)
  /** \brief __builtin_ffs function. */
  return __builtin_ffs(x);
#else
  int i;
  if (!x)
    return 0;
  for (i = 0; i < 32; i++) {
    if (x & (1 << i))
      return i + 1;
  }
  return 0;
#endif
}

LINUX_SYS_BITOPS_INLINE int posix_fls(int x) {
#if defined(__GNUC__) || defined(__clang__)
  if (!x)
    return 0;
  return 32 - __builtin_clz(x);
#else
  int i;
  if (!x)
    return 0;
  for (i = 31; i >= 0; i--) {
    if (x & (1 << i))
      return i + 1;
  }
  return 0;
#endif
}

#if defined(__GNUC__) || defined(__clang__)
#define LINUX_SYS_BITOPS_EXTENSION __extension__
#else
#define LINUX_SYS_BITOPS_EXTENSION
#endif

LINUX_SYS_BITOPS_EXTENSION LINUX_SYS_BITOPS_INLINE int
posix_fls64(unsigned long long x) {
#if defined(__GNUC__) || defined(__clang__)
  if (!x)
    return 0;
  return 64 - __builtin_clzll(x);
#else
  int i;
  if (!x)
    return 0;
  for (i = 63; i >= 0; i--) {
    if (x & (1ULL << i))
      return i + 1;
  }
  return 0;
#endif
}

LINUX_SYS_BITOPS_INLINE unsigned long posix___ffs(unsigned long word) {
#if defined(__GNUC__) || defined(__clang__)
  return (unsigned long)__builtin_ctzl(word);
#else
  int i;
  for (i = 0; i < (int)(sizeof(unsigned long) * 8); i++) {
    if (word & (1UL << i))
      return (unsigned long)i;
  }
  return 0;
#endif
}

LINUX_SYS_BITOPS_INLINE unsigned long posix_ffz(unsigned long word) {
  /** \brief posix___ffs function. */
  return posix___ffs(~word);
}

LINUX_SYS_BITOPS_INLINE void posix_set_bit(int nr,
                                           volatile unsigned long *addr) {
  unsigned long mask = 1UL << (nr % (sizeof(unsigned long) * 8));
  volatile unsigned long *p = addr + (nr / (sizeof(unsigned long) * 8));
#if defined(__GNUC__) || defined(__clang__)
  __sync_fetch_and_or(p, mask);
#else
  *p |= mask;
#endif
}

LINUX_SYS_BITOPS_INLINE void posix_clear_bit(int nr,
                                             volatile unsigned long *addr) {
  unsigned long mask = ~(1UL << (nr % (sizeof(unsigned long) * 8)));
  volatile unsigned long *p = addr + (nr / (sizeof(unsigned long) * 8));
#if defined(__GNUC__) || defined(__clang__)
  __sync_fetch_and_and(p, mask);
#else
  *p &= mask;
#endif
}

LINUX_SYS_BITOPS_INLINE void posix_change_bit(int nr,
                                              volatile unsigned long *addr) {
  unsigned long mask = 1UL << (nr % (sizeof(unsigned long) * 8));
  volatile unsigned long *p = addr + (nr / (sizeof(unsigned long) * 8));
#if defined(__GNUC__) || defined(__clang__)
  __sync_fetch_and_xor(p, mask);
#else
  *p ^= mask;
#endif
}

LINUX_SYS_BITOPS_INLINE int
posix_test_and_set_bit(int nr, volatile unsigned long *addr) {
  unsigned long mask = 1UL << (nr % (sizeof(unsigned long) * 8));
  volatile unsigned long *p = addr + (nr / (sizeof(unsigned long) * 8));
#if defined(__GNUC__) || defined(__clang__)
  unsigned long old = __sync_fetch_and_or(p, mask);
  return (old & mask) != 0;
#else
  unsigned long old = *p;
  *p |= mask;
  return (old & mask) != 0;
#endif
}

LINUX_SYS_BITOPS_INLINE int
posix_test_and_clear_bit(int nr, volatile unsigned long *addr) {
  unsigned long mask = 1UL << (nr % (sizeof(unsigned long) * 8));
  volatile unsigned long *p = addr + (nr / (sizeof(unsigned long) * 8));
#if defined(__GNUC__) || defined(__clang__)
  unsigned long old = __sync_fetch_and_and(p, ~mask);
  return (old & mask) != 0;
#else
  unsigned long old = *p;
  *p &= ~mask;
  return (old & mask) != 0;
#endif
}

LINUX_SYS_BITOPS_INLINE int
posix_test_and_change_bit(int nr, volatile unsigned long *addr) {
  unsigned long mask = 1UL << (nr % (sizeof(unsigned long) * 8));
  volatile unsigned long *p = addr + (nr / (sizeof(unsigned long) * 8));
#if defined(__GNUC__) || defined(__clang__)
  unsigned long old = __sync_fetch_and_xor(p, mask);
  return (old & mask) != 0;
#else
  unsigned long old = *p;
  *p ^= mask;
  return (old & mask) != 0;
#endif
}

LINUX_SYS_BITOPS_INLINE void posix___set_bit(int nr,
                                             volatile unsigned long *addr) {
  unsigned long mask = 1UL << (nr % (sizeof(unsigned long) * 8));
  volatile unsigned long *p = addr + (nr / (sizeof(unsigned long) * 8));
  *p |= mask;
}

LINUX_SYS_BITOPS_INLINE void posix___clear_bit(int nr,
                                               volatile unsigned long *addr) {
  unsigned long mask = ~(1UL << (nr % (sizeof(unsigned long) * 8)));
  volatile unsigned long *p = addr + (nr / (sizeof(unsigned long) * 8));
  *p &= mask;
}

LINUX_SYS_BITOPS_INLINE void posix___change_bit(int nr,
                                                volatile unsigned long *addr) {
  unsigned long mask = 1UL << (nr % (sizeof(unsigned long) * 8));
  volatile unsigned long *p = addr + (nr / (sizeof(unsigned long) * 8));
  *p ^= mask;
}

LINUX_SYS_BITOPS_INLINE int
posix___test_and_set_bit(int nr, volatile unsigned long *addr) {
  unsigned long mask = 1UL << (nr % (sizeof(unsigned long) * 8));
  volatile unsigned long *p = addr + (nr / (sizeof(unsigned long) * 8));
  unsigned long old = *p;
  *p |= mask;
  return (old & mask) != 0;
}

LINUX_SYS_BITOPS_INLINE int
posix___test_and_clear_bit(int nr, volatile unsigned long *addr) {
  unsigned long mask = 1UL << (nr % (sizeof(unsigned long) * 8));
  volatile unsigned long *p = addr + (nr / (sizeof(unsigned long) * 8));
  unsigned long old = *p;
  *p &= ~mask;
  return (old & mask) != 0;
}

LINUX_SYS_BITOPS_INLINE int
posix___test_and_change_bit(int nr, volatile unsigned long *addr) {
  unsigned long mask = 1UL << (nr % (sizeof(unsigned long) * 8));
  volatile unsigned long *p = addr + (nr / (sizeof(unsigned long) * 8));
  unsigned long old = *p;
  *p ^= mask;
  return (old & mask) != 0;
}

LINUX_SYS_BITOPS_INLINE int posix_test_bit(int nr,
                                           const volatile unsigned long *addr) {
  unsigned long mask = 1UL << (nr % (sizeof(unsigned long) * 8));
  const volatile unsigned long *p = addr + (nr / (sizeof(unsigned long) * 8));
  return (*p & mask) != 0;
}

#endif /* !_MSC_VER */

/* Map POSIX names to our posix_* implementations */
#ifndef ffs
#define ffs posix_ffs
#endif
#ifndef fls
#define fls posix_fls
#endif
#ifndef fls64
#define fls64 posix_fls64
#endif
#ifndef __ffs
#define __ffs posix___ffs
#endif
#ifndef ffz
#define ffz posix_ffz
#endif
#ifndef set_bit
#define set_bit posix_set_bit
#endif
#ifndef clear_bit
#define clear_bit posix_clear_bit
#endif
#ifndef change_bit
#define change_bit posix_change_bit
#endif
#ifndef test_and_set_bit
#define test_and_set_bit posix_test_and_set_bit
#endif
#ifndef test_and_clear_bit
#define test_and_clear_bit posix_test_and_clear_bit
#endif
#ifndef test_and_change_bit
#define test_and_change_bit posix_test_and_change_bit
#endif
#ifndef test_bit
#define test_bit posix_test_bit
#endif
#ifndef __set_bit
#define __set_bit posix___set_bit
#endif
#ifndef __clear_bit
#define __clear_bit posix___clear_bit
#endif
#ifndef __change_bit
#define __change_bit posix___change_bit
#endif
#ifndef __test_and_set_bit
#define __test_and_set_bit posix___test_and_set_bit
#endif
#ifndef __test_and_clear_bit
#define __test_and_clear_bit posix___test_and_clear_bit
#endif
#ifndef __test_and_change_bit
#define __test_and_change_bit posix___test_and_change_bit
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LINUX_SYS_BITOPS_H */
