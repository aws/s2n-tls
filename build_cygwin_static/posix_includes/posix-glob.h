/* posix-glob.h - Strict C89 Header */
#ifndef POSIX_GLOB_H
#define POSIX_GLOB_H

/* clang-format off */
#include <stddef.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Cross-Platform Printf Formatting */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* fnmatch */
/* ------------------------------------------------------------------------- */

/**
 * @defgroup fnmatch_flags Flags for fnmatch
 * @{
 */
#define FNM_PATHNAME                                                           \
  0x01                    /**< Slash in string only matches slash in pattern.  \
                           */
#define FNM_NOESCAPE 0x02 /**< Backslash is ordinary character. */
#define FNM_PERIOD                                                             \
  0x04 /**< Leading period in string must be exactly matched by period in      \
          pattern. */
/** @} */

#define FNM_NOMATCH 1 /**< Match failed. */

/**
 * @brief Match filename or pathname.
 *
 * @param pattern The pattern to match.
 * @param string The string to match against the pattern.
 * @param flags Flags modifying the match behavior.
 * @return 0 if the string matches the pattern, FNM_NOMATCH if there is no
 * match, or another non-zero value if there is an error.
 */
int fnmatch(const char *pattern, const char *string, int flags);

/* ------------------------------------------------------------------------- */
/* glob */
/* ------------------------------------------------------------------------- */

/**
 * @brief Structure describing a globbing match.
 */
typedef struct {
  size_t gl_pathc; /**< Count of paths matched so far. */
  char **gl_pathv; /**< List of matched pathnames. */
  size_t gl_offs;  /**< Slots to reserve in gl_pathv. */
} glob_t;

/**
 * @defgroup glob_flags Flags for glob
 * @{
 */
#define GLOB_ERR 0x01      /**< Return on read errors. */
#define GLOB_MARK 0x02     /**< Append a slash to each name. */
#define GLOB_NOSORT 0x04   /**< Don't sort the names. */
#define GLOB_DOOFFS 0x08   /**< Insert PGLOB->gl_offs NULLs. */
#define GLOB_NOCHECK 0x10  /**< If nothing matches, return the pattern. */
#define GLOB_APPEND 0x20   /**< Append to results of a previous call. */
#define GLOB_NOESCAPE 0x40 /**< Backslashes don't quote metacharacters. */
/** @} */

/**
 * @defgroup glob_errors Error returns for glob
 * @{
 */
#define GLOB_NOSPACE 1 /**< Ran out of memory. */
#define GLOB_ABORTED 2 /**< Read error. */
#define GLOB_NOMATCH 3 /**< No matches found. */
/** @} */

/**
 * @brief Find pathnames matching a pattern.
 *
 * @param pattern The pattern to match.
 * @param flags Flags modifying the match behavior.
 * @param errfunc Function to call on read error.
 * @param pglob Pointer to a glob_t structure to store the results.
 * @return 0 on success, or one of the GLOB_* error codes on failure.
 */
int glob(const char *pattern, int flags,
         int (*errfunc)(const char *epath, int eerrno), glob_t *pglob);

/**
 * @brief Free memory allocated by glob.
 *
 * @param pglob Pointer to a glob_t structure previously passed to glob.
 */
void globfree(glob_t *pglob);

/* ------------------------------------------------------------------------- */
/* wordexp */
/* ------------------------------------------------------------------------- */

/**
 * @brief Structure describing word expansion.
 */
typedef struct {
  size_t we_wordc; /**< Count of words matched by words. */
  char **we_wordv; /**< Pointer to list of expanded words. */
  size_t we_offs;  /**< Slots to reserve at the beginning of we_wordv. */
} wordexp_t;

/**
 * @defgroup wordexp_flags Flags for wordexp
 * @{
 */
#define WRDE_APPEND 0x01  /**< Append words to those previously generated. */
#define WRDE_DOOFFS 0x02  /**< Insert WE_OFFS NULLs. */
#define WRDE_NOCMD 0x04   /**< Don't do command substitution. */
#define WRDE_REUSE 0x08   /**< Reuse the wordexp_t structure. */
#define WRDE_SHOWERR 0x10 /**< Print error messages to stderr. */
#define WRDE_UNDEF 0x20   /**< Report error on an undefined variable. */
/** @} */

/**
 * @defgroup wordexp_errors Error returns for wordexp
 * @{
 */
#define WRDE_BADCHAR 1 /**< Unquoted special character. */
#define WRDE_BADVAL 2  /**< Undefined variable. */
#define WRDE_CMDSUB 3  /**< Command substitution not allowed. */
#define WRDE_NOSPACE 4 /**< Out of memory. */
#define WRDE_SYNTAX 5  /**< Syntax error. */
/** @} */

/**
 * @brief Perform word expansion.
 *
 * @param words The words to expand.
 * @param pwordexp Pointer to a wordexp_t structure to store the results.
 * @param flags Flags modifying the expansion behavior.
 * @return 0 on success, or one of the WRDE_* error codes on failure.
 */
int wordexp(const char *words, wordexp_t *pwordexp, int flags);

/**
 * @brief Free memory allocated by wordexp.
 *
 * @param pwordexp Pointer to a wordexp_t structure previously passed to
 * wordexp.
 */
void wordfree(wordexp_t *pwordexp);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_GLOB_H */
