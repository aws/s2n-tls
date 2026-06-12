
#ifdef __cplusplus
extern "C" {
#endif

/* posix-libgen.h - Strict C89 Header */
#ifndef POSIX_LIBGEN_H
#define POSIX_LIBGEN_H

/**
 * @file posix-libgen.h
 * @brief POSIX libgen.h implementation for MSVC
 *
 * This header provides the POSIX basename() and dirname() functions,
 * implemented using safe Microsoft CRT extensions.
 */

/**
 * @brief Returns the last component of a pathname.
 *
 * The basename() function takes the pathname pointed to by path and returns a
 * pointer to the final component of the pathname, deleting any trailing
 * '/' or '\\' characters.
 *
 * If the string consists entirely of the '/' or '\\' character, basename()
 * returns a pointer to the string "/" or "\\".
 * If path is a null pointer or points to an empty string, basename() returns
 * a pointer to the string ".".
 *
 * @param path The pathname to parse. This string may be modified.
 * @return A pointer to the final component of the path.
 */
char *basename(char *path);

/**
 * @brief Returns the directory name of a pathname.
 *
 * The dirname() function takes a pointer to a character string that contains
 * a pathname, and returns a pointer to a string that is a pathname of the
 * parent directory of that file. Trailing '/' or '\\' characters in the path
 * are not counted as part of the path.
 *
 * If path does not contain a '/' or '\\', then dirname() returns a pointer to
 * the string ".". If path is a null pointer or points to an empty string,
 * dirname() returns a pointer to the string ".".
 *
 * @param path The pathname to parse. This string may be modified.
 * @return A pointer to the parent directory of the path.
 */
char *dirname(char *path);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_LIBGEN_H */
