#pragma once
#include <stdbool.h>

#include "api/s2n.h"

typedef struct {
    int __error_signal;
} s2n_result;

s2n_result __STUB_RESULT_OK(void);
s2n_result __STUB_RESULT_ERROR(void);

#define S2N_RESULT_OK __STUB_RESULT_OK()
#define S2N_RESULT_ERROR __STUB_RESULT_ERROR()

/* TODO can we pass this along to rust? */
#define S2N_RESULT_MUST_USE

bool __STUB_RESULT_IS_OK(s2n_result result);
#define s2n_result_is_ok __STUB_RESULT_IS_OK

bool __STUB_RESULT_IS_ERROR(s2n_result result);
#define s2n_result_is_error __STUB_RESULT_IS_ERROR

void __STUB_RESULT_IGNORE(s2n_result result);
#define s2n_result_ignore __STUB_RESULT_IGNORE

#define S2N_RESULT s2n_result
#define S2N_CLEANUP_RESULT s2n_result
