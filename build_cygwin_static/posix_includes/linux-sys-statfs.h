
#ifdef __cplusplus
extern "C" {
#endif

#ifndef LINUX_SYS_STATFS_H
#define LINUX_SYS_STATFS_H

#if defined(_MSC_VER)

struct statfs {
  long f_type;
  long f_bsize;
  long f_blocks;
  long f_bfree;
  long f_bavail;
  long f_files;
  long f_ffree;
  long f_fsid[2];
  long f_namelen;
  long f_frsize;
  long f_flags;
  long f_spare[4];
};

/** \brief statfs function. */
int statfs(const char *path, struct statfs *buf);
/** \brief fstatfs function. */
int fstatfs(int fd, struct statfs *buf);

#endif /* _MSC_VER */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LINUX_SYS_STATFS_H */
