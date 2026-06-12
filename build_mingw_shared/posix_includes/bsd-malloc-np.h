
#ifdef __cplusplus
extern "C" {
#endif

#ifndef BSD_MALLOC_NP_H
#define BSD_MALLOC_NP_H

#if defined(_MSC_VER) && !defined(__clang__)
/** \brief je_malloc_stats_print function. */
void je_malloc_stats_print(void (*write_cb)(void *, const char *),
                           void *cbopaque, const char *opts);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
