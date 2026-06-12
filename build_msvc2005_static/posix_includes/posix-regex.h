#ifndef POSIX_REGEX_H
#define POSIX_REGEX_H

/* clang-format off */
#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__) ||       \
    defined(__MSDOS__) || defined(__WATCOMC__)

#include <stddef.h>

typedef struct {
  int re_magic;
  size_t re_nsub;
  const char *re_endp;
  void *re_guts;
} regex_t;

typedef int regoff_t;

typedef struct {
  regoff_t rm_so;
  regoff_t rm_eo;
} regmatch_t;

#define REG_BASIC 0000
#define REG_EXTENDED 0001
#define REG_ICASE 0002
#define REG_NOSUB 0004
#define REG_NEWLINE 0010
#define REG_NOSPEC 0020
#define REG_PEND 0040
#define REG_DUMP 0200

#define REG_NOTBOL 00001
#define REG_NOTEOL 00002
#define REG_STARTEND 00004
#define REG_TRACE 00400
#define REG_LARGE 01000
#define REG_BACKR 02000

#define REG_NOMATCH 1
#define REG_BADPAT 2
#define REG_ECOLLATE 3
#define REG_ECTYPE 4
#define REG_EESCAPE 5
#define REG_ESUBREG 6
#define REG_EBRACK 7
#define REG_EPAREN 8
#define REG_EBRACE 9
#define REG_BADBR 10
#define REG_ERANGE 11
#define REG_ESPACE 12
#define REG_BADRPT 13
#define REG_EMPTY 14
#define REG_ASSERT 15
#define REG_INVARG 16
#define REG_ILLSEQ 17
#define REG_ENOSYS 18

/** \brief regcomp function. */
int regcomp(regex_t *preg, const char *pattern, int cflags);
/** \brief regexec function. */
int regexec(const regex_t *preg, const char *string, size_t nmatch,
            regmatch_t pmatch[], int eflags);
/** \brief regerror function. */
size_t regerror(int errcode, const regex_t *preg, char *errbuf,
                size_t errbuf_size);
/** \brief regfree function. */
void regfree(regex_t *preg);

#else
#include <regex.h>
#endif
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

/* Any functions to declare here? None */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_REGEX_H */
