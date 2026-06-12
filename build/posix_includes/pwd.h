/* Strict C89 pwd.h wrapper */
#ifndef POSIX_PWDGRP_PWD_H
#define POSIX_PWDGRP_PWD_H

#ifdef __cplusplus
extern "C" {
#endif

/* clang-format off */
#include <posix-types.h>
/* clang-format on */

struct passwd {
  char *pw_name;
  char *pw_passwd;
  uid_t pw_uid;
  gid_t pw_gid;
  char *pw_gecos;
  char *pw_dir;
  char *pw_shell;
};

struct passwd *getpwnam(const char *name);
struct passwd *getpwuid(uid_t uid);
int getpwnam_r(const char *name, struct passwd *pwd, char *buffer,
               size_t bufsize, struct passwd **result);
int getpwuid_r(uid_t uid, struct passwd *pwd, char *buffer, size_t bufsize,
               struct passwd **result);
void endpwent(void);
struct passwd *getpwent(void);
void setpwent(void);

#ifdef __cplusplus
}
#endif

#endif /* POSIX_PWDGRP_PWD_H */
