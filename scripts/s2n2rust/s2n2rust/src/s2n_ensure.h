#pragma once

#include <stdbool.h>
#include <stddef.h>
#include "utils/s2n_result.h"

void __STUB_POSIX_ENSURE(bool is_ok, int error);
void __STUB_POSIX_ENSURE_REF(const void* ref);
void __STUB_POSIX_ENSURE_MUT(void* ref);
void __STUB_POSIX_ENSURE_DEBUG(bool is_ok, int error);
void __STUB_POSIX_GUARD(bool is_ok);
void __STUB_POSIX_GUARD_OSSL(int result, int error);
void __STUB_POSIX_GUARD_RESULT(bool is_ok);
void __STUB_POSIX_GUARD_PTR(bool is_ok);
void __STUB_POSIX_PRECONDITION(s2n_result result);
void __STUB_POSIX_POSTCONDITION(s2n_result result);
int __STUB_POSIX_BAIL(int error);
void __STUB_POSIX_MEMMOVE(void* dest, const void* src, size_t len);

void __STUB_RESULT_ENSURE(bool is_ok, int error);
void __STUB_RESULT_ENSURE_REF(const void* ref);
void __STUB_RESULT_ENSURE_MUT(void* ref);
void __STUB_RESULT_ENSURE_DEBUG(bool is_ok, int error);
void __STUB_RESULT_GUARD(bool is_ok);
void __STUB_RESULT_GUARD_OSSL(int result, int error);
void __STUB_RESULT_GUARD_POSIX(bool is_ok);
void __STUB_RESULT_GUARD_PTR(bool is_ok);
void __STUB_RESULT_PRECONDITION(s2n_result result);
void __STUB_RESULT_POSTCONDITION(s2n_result result);
s2n_result __STUB_RESULT_BAIL(int error);
void __STUB_RESULT_MEMMOVE(void* dest, const void* src, size_t len);

void __STUB_PTR_ENSURE(bool is_ok, int error);
void __STUB_PTR_ENSURE_REF(const void* ref);
void __STUB_PTR_ENSURE_MUT(void* ref);
void __STUB_PTR_ENSURE_DEBUG(bool is_ok, int error);
void __STUB_PTR_GUARD(bool is_ok);
void __STUB_PTR_GUARD_OSSL(int result, int error);
void __STUB_PTR_GUARD_POSIX(bool is_ok);
void __STUB_PTR_GUARD_RESULT(bool is_ok);
void __STUB_PTR_PRECONDITION(s2n_result result);
void __STUB_PTR_POSTCONDITION(s2n_result result);
void* __STUB_PTR_BAIL(int error);
void __STUB_PTR_MEMMOVE(void* dest, const void* src, size_t len);

#define __S2N_ENSURE_SAFE_MEMSET(d, c, n, guard) \
    do {                                         \
        __typeof(n) __tmp_n = (n);               \
        if (s2n_likely(__tmp_n)) {               \
            __typeof(d) __tmp_d = (d);           \
            guard(__tmp_d);                      \
            memset(__tmp_d, (c), __tmp_n);       \
        }                                        \
    } while (0)

bool __STUB_S2N_LIKELY(bool x);
#define s2n_likely(x) __STUB_S2N_LIKELY(!!(x))

bool __STUB_S2N_UNLIKELY(bool x);
#define s2n_unlikely(x) __STUB_S2N_UNLIKELY(!!(x))

#define S2N_MEM_IS_READABLE_CHECK(base, len) (((len) == 0) || (base) != NULL)
#define S2N_MEM_IS_WRITABLE_CHECK(base, len) (((len) == 0) || (base) != NULL)
#define S2N_MEM_IS_READABLE(base, len)  (((len) == 0) || (base) != NULL)
#define S2N_MEM_IS_WRITABLE(base, len)  (((len) == 0) || (base) != NULL)
#define S2N_OBJECT_PTR_IS_READABLE(ptr) ((ptr) != NULL)
#define S2N_OBJECT_PTR_IS_WRITABLE(ptr) ((ptr) != NULL)

bool __STUB_IMPLIES(bool a, bool b);
#define S2N_IMPLIES(a, b) __STUB_IMPLIES((a), (b))

bool __STUB_IFF(bool a, bool b);
#define S2N_IFF(a, b) __STUB_IFF((a), (b))
