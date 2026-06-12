#if defined(__GNUC__)
#pragma GCC system_header
#endif
/* posix-dirent.h - Strict C89 Header */
#ifndef POSIX_DIRENT_H
#define POSIX_DIRENT_H

#if !defined(_WIN32) && !defined(__WIN32__) && !defined(WIN32)

/* On non-Windows platforms, simply include the standard dirent.h */
/* clang-format off */
#if defined(__WATCOMC__)
#include <direct.h>
#else
#if defined(__GNUC__) || defined(__clang__)
#include_next <dirent.h>
#else
#include <dirent.h>
#endif
#endif
#include <sys/types.h>

#else /* _WIN32 */

#include <stddef.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

/* File types for d_type */
#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
#define DT_WHT 14

/**
 * @struct dirent
 * @brief Represents a directory entry.
 */
struct dirent {
  long d_ino;              /**< Inode number (always 0 on Windows) */
  long d_off;              /**< Offset to the next dirent */
  unsigned short d_reclen; /**< Length of this record */
  unsigned char d_type;    /**< Type of file */
  char d_name[260];        /**< File name (Windows MAX_PATH is 260) */
};

/**
 * @struct DIR
 * @brief Opaque directory stream structure.
 */
typedef struct DIR DIR;

/**
 * @brief Opens a directory stream.
 * @param name The name of the directory to open.
 * @return A pointer to the directory stream, or NULL if an error occurred.
 */
DIR *opendir(const char *name);

/**
 * @brief Reads a directory entry from the given directory stream.
 * @param dirp The directory stream.
 * @return A pointer to the next directory entry, or NULL if the end of the
 * directory stream is reached or an error occurred.
 */
struct dirent *readdir(DIR *dirp);

/**
 * @brief Closes the given directory stream.
 * @param dirp The directory stream.
 * @return 0 on success, or -1 on error.
 */
int closedir(DIR *dirp);

/**
 * @brief Resets the position of the directory stream to the beginning of the
 * directory.
 * @param dirp The directory stream.
 */
void rewinddir(DIR *dirp);

/**
 * @brief Sets the position of the next readdir() call in the directory stream.
 * @param dirp The directory stream.
 * @param loc The position to seek to.
 */
void seekdir(DIR *dirp, long loc);

/**
 * @brief Returns the current location associated with the directory stream.
 * @param dirp The directory stream.
 * @return The current location.
 */
long telldir(DIR *dirp);

/**
 * @brief Scans a directory for entries.
 * @param dirp The name of the directory to scan.
 * @param namelist Pointer to an array of pointers to directory entries.
 * @param filter A function pointer to a filter function, or NULL.
 * @param compar A function pointer to a comparison function.
 * @return The number of entries selected, or -1 on error.
 */
int scandir(const char *dirp, struct dirent ***namelist,
            int (*filter)(const struct dirent *),
            int (*compar)(const struct dirent **, const struct dirent **));

/**
 * @brief Compares two directory entries for sorting alphabetically.
 * @param a Pointer to the first directory entry pointer.
 * @param b Pointer to the second directory entry pointer.
 * @return An integer less than, equal to, or greater than zero if the first
 * string is less than, equal to, or greater than the second string.
 */
int alphasort(const struct dirent **a, const struct dirent **b);

#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_DIRENT_H */
