#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "api/s2n.h"
#include "utils/s2n_ensure.h"

struct s2n_debug_info {
    const char *debug_str;
};

struct s2n_debug_info* __STUB_DEBUG_INFO_GET(void);
#define _s2n_debug_info *__STUB_DEBUG_INFO_GET()

void __STUB_DEBUG_INFO_SET(struct s2n_debug_info debug_info);
#define _s2n_debug_info_set __STUB_DEBUG_INFO_SET

void __STUB_ERROR_PRESERVE_ERRNO(void);
#define S2N_ERROR_PRESERVE_ERRNO __STUB_ERROR_PRESERVE_ERRNO

bool __STUB_ERROR_IS_BLOCKING(int error);
#define S2N_ERROR_IS_BLOCKING(x) __STUB_ERROR_IS_BLOCKING(x)

void __STUB_POSIX_ERROR_IF(bool is_ok, int error);
#define S2N_ERROR_IF(condition, error) __STUB_POSIX_ERROR_IF(!!(condition), (error))

typedef enum {
    S2N_ERR_NUM_VALUE_BITS = 26,
} s2n_errno_start_value_bits;

typedef enum {
    S2N_ERR_T_OK_START = (S2N_ERR_T_OK << S2N_ERR_NUM_VALUE_BITS),
    S2N_ERR_T_IO_START = (S2N_ERR_T_IO << S2N_ERR_NUM_VALUE_BITS),
    S2N_ERR_T_CLOSED_START =  (S2N_ERR_T_CLOSED << S2N_ERR_NUM_VALUE_BITS),
    S2N_ERR_T_BLOCKED_START = (S2N_ERR_T_BLOCKED << S2N_ERR_NUM_VALUE_BITS),
    S2N_ERR_T_ALERT_START  =  (S2N_ERR_T_ALERT << S2N_ERR_NUM_VALUE_BITS),
    S2N_ERR_T_PROTO_START  =  (S2N_ERR_T_PROTO << S2N_ERR_NUM_VALUE_BITS),
    S2N_ERR_T_INTERNAL_START = (S2N_ERR_T_INTERNAL << S2N_ERR_NUM_VALUE_BITS),
    S2N_ERR_T_USAGE_START  =  (S2N_ERR_T_USAGE << S2N_ERR_NUM_VALUE_BITS),
} s2n_errno_start;
