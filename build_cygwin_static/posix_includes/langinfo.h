/* posix-langinfo/include/langinfo.h - Strict C89 Implementation */
#ifndef POSIX_LANGINFO_H
#define POSIX_LANGINFO_H

#if defined(_MSC_VER) && !defined(__clang__)
#define POSIX_LANGINFO_MSVC 1
#endif

#if defined(POSIX_LANGINFO_MSVC) || defined(_WIN32) || defined(__MSDOS__) ||   \
    defined(__WATCOMC__)

/** \brief The type used to identify langinfo items. */
typedef int nl_item;

/** \brief Character encoding name. */
#define CODESET 1
/** \brief String for formatting date and time. */
#define D_T_FMT 2
/** \brief Date format string. */
#define D_FMT 3
/** \brief Time format string. */
#define T_FMT 4
/** \brief AM/PM time format string. */
#define T_FMT_AMPM 5
/** \brief Ante Meridian affix. */
#define AM_STR 6
/** \brief Post Meridian affix. */
#define PM_STR 7
/** \brief Name of the first day of the week (Sunday). */
#define DAY_1 8
/** \brief Name of the second day of the week (Monday). */
#define DAY_2 9
/** \brief Name of the third day of the week (Tuesday). */
#define DAY_3 10
/** \brief Name of the fourth day of the week (Wednesday). */
#define DAY_4 11
/** \brief Name of the fifth day of the week (Thursday). */
#define DAY_5 12
/** \brief Name of the sixth day of the week (Friday). */
#define DAY_6 13
/** \brief Name of the seventh day of the week (Saturday). */
#define DAY_7 14
/** \brief Abbreviated name of the first day of the week. */
#define ABDAY_1 15
/** \brief Abbreviated name of the second day of the week. */
#define ABDAY_2 16
/** \brief Abbreviated name of the third day of the week. */
#define ABDAY_3 17
/** \brief Abbreviated name of the fourth day of the week. */
#define ABDAY_4 18
/** \brief Abbreviated name of the fifth day of the week. */
#define ABDAY_5 19
/** \brief Abbreviated name of the sixth day of the week. */
#define ABDAY_6 20
/** \brief Abbreviated name of the seventh day of the week. */
#define ABDAY_7 21
/** \brief Name of the first month of the year. */
#define MON_1 22
/** \brief Name of the second month of the year. */
#define MON_2 23
/** \brief Name of the third month of the year. */
#define MON_3 24
/** \brief Name of the fourth month of the year. */
#define MON_4 25
/** \brief Name of the fifth month of the year. */
#define MON_5 26
/** \brief Name of the sixth month of the year. */
#define MON_6 27
/** \brief Name of the seventh month of the year. */
#define MON_7 28
/** \brief Name of the eighth month of the year. */
#define MON_8 29
/** \brief Name of the ninth month of the year. */
#define MON_9 30
/** \brief Name of the tenth month of the year. */
#define MON_10 31
/** \brief Name of the eleventh month of the year. */
#define MON_11 32
/** \brief Name of the twelfth month of the year. */
#define MON_12 33
/** \brief Abbreviated name of the first month. */
#define ABMON_1 34
/** \brief Abbreviated name of the second month. */
#define ABMON_2 35
/** \brief Abbreviated name of the third month. */
#define ABMON_3 36
/** \brief Abbreviated name of the fourth month. */
#define ABMON_4 37
/** \brief Abbreviated name of the fifth month. */
#define ABMON_5 38
/** \brief Abbreviated name of the sixth month. */
#define ABMON_6 39
/** \brief Abbreviated name of the seventh month. */
#define ABMON_7 40
/** \brief Abbreviated name of the eighth month. */
#define ABMON_8 41
/** \brief Abbreviated name of the ninth month. */
#define ABMON_9 42
/** \brief Abbreviated name of the tenth month. */
#define ABMON_10 43
/** \brief Abbreviated name of the eleventh month. */
#define ABMON_11 44
/** \brief Abbreviated name of the twelfth month. */
#define ABMON_12 45
/** \brief Era description segments. */
#define ERA 46
/** \brief Era date format string. */
#define ERA_D_FMT 47
/** \brief Era date and time format string. */
#define ERA_D_T_FMT 48
/** \brief Era time format string. */
#define ERA_T_FMT 49
/** \brief Alternative symbols for digits. */
#define ALT_DIGITS 50
/** \brief Radix character. */
#define RADIXCHAR 51
/** \brief Separator for thousands. */
#define THOUSEP 52
/** \brief Affirmative response expression. */
#define YESEXPR 53
/** \brief Negative response expression. */
#define NOEXPR 54
/** \brief Local currency symbol. */
#define CRNCYSTR 55

/**
 * \brief Return language information.
 *
 * \param item The language information item to retrieve.
 * \return A pointer to a string containing the requested information.
 */
char *posix_langinfo(nl_item item);

#ifndef nl_langinfo
#define nl_langinfo posix_langinfo
#endif

#else
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC system_header
#endif
/* clang-format off */
#include_next <langinfo.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_LANGINFO_H */
