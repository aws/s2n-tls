/* Strict C89 grp.h wrapper */
#ifndef POSIX_PWDGRP_GRP_H
#define POSIX_PWDGRP_GRP_H

#ifdef __cplusplus
extern "C" {
#endif

/* clang-format off */
#include <posix-types.h>
/* clang-format on */

struct group {
  char *gr_name;
  char *gr_passwd;
  gid_t gr_gid;
  char **gr_mem;
};

struct group *getgrnam(const char *name);
struct group *getgrgid(gid_t gid);
int getgrnam_r(const char *name, struct group *grp, char *buffer,
               size_t bufsize, struct group **result);
int getgrgid_r(gid_t gid, struct group *grp, char *buffer, size_t bufsize,
               struct group **result);
void endgrent(void);
struct group *getgrent(void);
void setgrent(void);

#ifdef __cplusplus
}
#endif

#endif /* POSIX_PWDGRP_GRP_H */
