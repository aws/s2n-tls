/* posix-syslog.h - Strict C89 Header */
#ifndef POSIX_SYSLOG_H
#define POSIX_SYSLOG_H

/* clang-format off */
#include <stdarg.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

/* Format specifier macro as requested */

/* Priorities */
#define LOG_EMERG 0   /* system is unusable */
#define LOG_ALERT 1   /* action must be taken immediately */
#define LOG_CRIT 2    /* critical conditions */
#define LOG_ERR 3     /* error conditions */
#define LOG_WARNING 4 /* warning conditions */
#define LOG_NOTICE 5  /* normal but significant condition */
#define LOG_INFO 6    /* informational */
#define LOG_DEBUG 7   /* debug-level messages */

/* Facilities */
#define LOG_KERN (0 << 3)      /* kernel messages */
#define LOG_USER (1 << 3)      /* random user-level messages */
#define LOG_MAIL (2 << 3)      /* mail system */
#define LOG_DAEMON (3 << 3)    /* system daemons */
#define LOG_AUTH (4 << 3)      /* security/authorization messages */
#define LOG_SYSLOG (5 << 3)    /* messages generated internally by syslogd */
#define LOG_LPR (6 << 3)       /* line printer subsystem */
#define LOG_NEWS (7 << 3)      /* network news subsystem */
#define LOG_UUCP (8 << 3)      /* UUCP subsystem */
#define LOG_CRON (9 << 3)      /* clock daemon */
#define LOG_AUTHPRIV (10 << 3) /* security/authorization messages (private) */
#define LOG_FTP (11 << 3)      /* ftp daemon */
#define LOG_LOCAL0 (16 << 3)   /* reserved for local use */
#define LOG_LOCAL1 (17 << 3)   /* reserved for local use */
#define LOG_LOCAL2 (18 << 3)   /* reserved for local use */
#define LOG_LOCAL3 (19 << 3)   /* reserved for local use */
#define LOG_LOCAL4 (20 << 3)   /* reserved for local use */
#define LOG_LOCAL5 (21 << 3)   /* reserved for local use */
#define LOG_LOCAL6 (22 << 3)   /* reserved for local use */
#define LOG_LOCAL7 (23 << 3)   /* reserved for local use */

/* Options */
#define LOG_PID 0x01    /* log the pid with each message */
#define LOG_CONS 0x02   /* log on the console if errors in sending */
#define LOG_ODELAY 0x04 /* delay open until first syslog() (default) */
#define LOG_NDELAY 0x08 /* don't delay open */
#define LOG_NOWAIT 0x10 /* don't wait for console forks: DEPRECATED */
#define LOG_PERROR 0x20 /* log to stderr as well */

/* Macros */
#define LOG_MAKEPRI(fac, pri) ((fac) | (pri))
#define LOG_PRI(p) ((p) & 7)
#define LOG_FAC(p) (((p) & 0x03f8) >> 3)
#define LOG_MASK(pri) (1 << (pri))
#define LOG_UPTO(pri) ((1 << ((pri) + 1)) - 1)

/* Functions */

/**
 * @brief Close the log
 *
 * Closes the descriptor being used to write to the system logger.
 */
void closelog(void);

/**
 * @brief Open a connection to the system logger
 *
 * @param ident The string to prepend to every message.
 * @param option Logging options (e.g., LOG_PID, LOG_NDELAY).
 * @param facility The default facility to assign to messages.
 */
void openlog(const char *ident, int option, int facility);

/**
 * @brief Set the log priority mask
 *
 * @param mask The new log priority mask.
 * @return The previous log priority mask.
 */
int setlogmask(int mask);

/**
 * @brief Generate a log message
 *
 * @param priority The priority and facility of the message.
 * @param format The format string, followed by format arguments.
 */
void syslog(int priority, const char *format, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_SYSLOG_H */
