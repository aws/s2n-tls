
#ifdef __cplusplus
extern "C" {
#endif

#ifndef LINUX_GETOPT_H
#define LINUX_GETOPT_H

#if defined(_MSC_VER)

extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

struct option {
  const char *name;
  int has_arg;
  int *flag;
  int val;
};

#define no_argument 0
#define required_argument 1
#define optional_argument 2

/** \brief getopt function. */
int getopt(int argc, char *const argv[], const char *optstring);
/** \brief getopt_long function. */
int getopt_long(int argc, char *const argv[], const char *optstring,
                const struct option *longopts, int *longindex);

#endif /* _MSC_VER */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LINUX_GETOPT_H */
