/* posix-dlfcn.h - Strict C89 Header */
#ifndef POSIX_DLFCN_H
#define POSIX_DLFCN_H

#if defined(__linux__) || defined(__CYGWIN__) || defined(__APPLE__) ||         \
    defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) ||     \
    defined(__sun) || defined(__QNX__)
/* clang-format off */
#include <dlfcn.h>
#else
#include <stddef.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file posix-dlfcn.h
 * @brief Strict C89 POSIX dlfcn.h implementation for MSVC
 *
 * This header provides the standard POSIX dynamic linking interface
 * implemented over native Windows APIs (LoadLibrary, GetProcAddress, etc.).
 */

/** @brief Resolve symbol when the first reference is made to it. */
#define RTLD_LAZY 1

/** @brief Resolve all undefined symbols in the library before dlopen() returns.
 */
#define RTLD_NOW 2

/** @brief Symbols defined by this library will be made available for symbol
 * resolution of subsequently loaded libraries. */
#define RTLD_GLOBAL 4

/** @brief Symbols defined in this library are not made available to resolve
 * references in subsequently loaded libraries. */
#define RTLD_LOCAL 8

#ifndef RTLD_DEFAULT
/** @brief Special handle to find the first occurrence of the desired symbol
 * using the default library search order. */
#define RTLD_DEFAULT ((void *)0)
#endif

#ifndef RTLD_NEXT
/** @brief Special handle to find the next occurrence of a symbol in the search
 * order after the current library. */
#define RTLD_NEXT ((void *)(size_t)-1)
#endif

/**
 * @struct Dl_info
 * @brief Information about a dynamically loaded object's symbol.
 */
typedef struct {
  const char *dli_fname; /**< File name of defining object. */
  void *dli_fbase;       /**< Load address of that object. */
  const char *dli_sname; /**< Name of nearest symbol. */
  void *dli_saddr;       /**< Exact value of nearest symbol. */
} Dl_info;

/**
 * @brief Opens a dynamic library and returns a handle.
 *
 * Maps to LoadLibraryA on Windows. If file is NULL, returns a handle
 * to the main executable via GetModuleHandleA(NULL).
 *
 * @param file The path to the dynamic library, or NULL for the main executable.
 * @param mode A bitwise OR of RTLD_LAZY, RTLD_NOW, RTLD_GLOBAL, RTLD_LOCAL.
 * (Ignored on Windows).
 * @return A handle to the loaded library, or NULL on error.
 */
void *dlopen(const char *file, int mode);

/**
 * @brief Obtains the address of a symbol within a dynamic library.
 *
 * Maps to GetProcAddress on Windows. Supports RTLD_DEFAULT by searching
 * the main executable. RTLD_NEXT is not supported on Windows.
 *
 * @param handle The library handle returned by dlopen, or a special handle
 * (e.g., RTLD_DEFAULT).
 * @param name The name of the symbol to find.
 * @return The address of the symbol, or NULL on error.
 */
void *dlsym(void *handle, const char *name);

/**
 * @brief Closes a dynamic library handle.
 *
 * Maps to FreeLibrary on Windows. Does not close the main executable handle.
 *
 * @param handle The library handle to close.
 * @return 0 on success, or a non-zero value on error.
 */
int dlclose(void *handle);

/**
 * @brief Returns a human-readable string describing the most recent error.
 *
 * Maps Windows GetLastError to a string via FormatMessageA. The error state
 * is thread-local. A call to dlerror clears the pending error condition.
 *
 * @return A string describing the error, or NULL if no error has occurred
 *         since the last call to dlerror.
 */
char *dlerror(void);

/**
 * @brief Translates an address to symbol information.
 *
 * Uses VirtualQuery and GetModuleFileNameA to find the module name and base
 * address for the given memory address. The nearest symbol name and address
 * are not resolved (returns NULL for those fields).
 *
 * @param addr The address to look up.
 * @param info A pointer to a Dl_info struct to populate.
 * @return Non-zero on success, or 0 on error.
 */
int dladdr(const void *addr, Dl_info *info);

#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_DLFCN_H */
