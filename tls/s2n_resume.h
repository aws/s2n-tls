#pragma once

#include "tls/s2n_connection.h"

#include "utils/s2n_blob.h"

#define S2N_SERIALIZED_FORMAT_VERSION   1
#define S2N_STATE_LIFETIME_IN_NANOS     21600000000
#define S2N_STATE_SIZE_IN_BYTES         (1 + 8 + 1 + S2N_TLS_CIPHER_SUITE_LEN + S2N_TLS_SECRET_LEN)

extern int s2n_is_caching_enabled(struct s2n_config *config);
extern int s2n_resume_from_cache(struct s2n_connection *conn);
extern int s2n_store_to_cache(struct s2n_connection *conn);
