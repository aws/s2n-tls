#pragma once

#define GUARD_EXIT(x, msg)  \
  do {                      \
    if ((x) < 0) {          \
      print_s2n_error(msg); \
      exit(1);              \
    }                       \
  } while (0)

#define GUARD_RETURN(x, msg) \
  do {                       \
    if ((x) < 0) {           \
      print_s2n_error(msg);  \
      return -1;             \
    }                        \
  } while (0)
