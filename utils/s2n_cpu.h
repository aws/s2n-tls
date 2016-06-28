#pragma once

#include "utils/s2n_blob.h"

extern int s2n_cpu_supports_rdrand();
extern int s2n_cpu_get_rdrand_data(struct s2n_blob *out);
extern int s2n_cpu_supports_aesni();
