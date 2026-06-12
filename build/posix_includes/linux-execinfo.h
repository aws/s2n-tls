#ifndef LINUX_EXECINFO_H
#define LINUX_EXECINFO_H

/* clang-format off */
#if defined(_MSC_VER)
#include <stddef.h>
/* clang-format on */
#endif /* _MSC_VER */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER)

/** \brief backtrace function. */
int backtrace(void **buffer, int size);
char **backtrace_symbols(void *const *buffer, int size);
/** \brief backtrace_symbols_fd function. */
void backtrace_symbols_fd(void *const *buffer, int size, int fd);

#endif /* _MSC_VER */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LINUX_EXECINFO_H */
