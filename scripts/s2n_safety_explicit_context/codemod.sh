#!/usr/bin/env bash

# Idempotently applies a codemod script to update safety macro calls to include the
# context in which they're used.

set -e

SCRIPT_DIR=scripts/s2n_safety_explicit_context

if [ ! -d $SCRIPT_DIR/.venv ]; then
  python3 -m venv $SCRIPT_DIR/.venv
fi

source $SCRIPT_DIR/.venv/bin/activate
pip install -r $SCRIPT_DIR/requirements.txt

set -x

function join { local IFS=","; echo "$*"; }

IGNORES=$(
    join \
        api \
        cmake \
        codebuild \
        coverage \
        docker-images \
        docs \
        error \
        lib \
        libcrypto-build \
        libcrypto-root \
        scram \
        scripts \
        utils/s2n_safety.h \
        utils/s2n_safety_macros.h \
)

function mod {
  codemod \
    --exclude-paths $IGNORES \
    --extensions c,h,patch \
    "$1" "$2"
}

function map {
  mod "( +)$1 *\(" "\1$2("
  mod "^$1 *\(" "$2("
}

# PTR
map BAIL_PTR               PTR_BAIL
map S2N_ERROR_PTR          PTR_BAIL
map ENSURE_PTR             PTR_ENSURE
map ENSURE_REF_PTR         PTR_ENSURE_REF
map ENSURE_MUT_PTR         PTR_ENSURE_MUT
map GUARD_PTR              PTR_GUARD_POSIX
map GUARD_POSIX_PTR        PTR_GUARD_POSIX
map GUARD_NONNULL_PTR      PTR_GUARD_NONNULL
map GUARD_RESULT_PTR       PTR_GUARD_RESULT
map notnull_check_ptr      PTR_ENSURE_REF

# POSIX
map BAIL_POSIX             POSIX_BAIL
map S2N_ERROR              POSIX_BAIL
map ENSURE_POSIX           POSIX_ENSURE
map ENSURE_POSIX_REF       POSIX_ENSURE_REF
map ENSURE_POSIX_MUT       POSIX_ENSURE_MUT
map notnull_check          POSIX_ENSURE_REF
map PRECONDITION_POSIX     POSIX_PRECONDITION
map POSTCONDITION_POSIX    POSIX_POSTCONDITION
map GUARD                  POSIX_GUARD
map GUARD_NONNULL          POSIX_GUARD_PTR
map GUARD_POSIX_NONNULL    POSIX_GUARD_PTR
map GUARD_OSSL             POSIX_GUARD_OSSL
map GUARD_POSIX_OSSL       POSIX_GUARD_OSSL
map GUARD_AS_POSIX         POSIX_GUARD_RESULT
map GUARD_POSIX            POSIX_GUARD
map GUARD_POSIX_STRICT     POSIX_GUARD_STRICT
map gte_check              POSIX_ENSURE_GTE
map lte_check              POSIX_ENSURE_LTE
map gt_check               POSIX_ENSURE_GT
map lt_check               POSIX_ENSURE_LT
map eq_check               POSIX_ENSURE_EQ
map ne_check               POSIX_ENSURE_NE
map inclusive_range_check  POSIX_ENSURE_INCLUSIVE_RANGE
map exclusive_range_check  POSIX_ENSURE_EXCLUSIVE_RANGE
map memcpy_check           POSIX_CHECKED_MEMCPY
map memset_check           POSIX_CHECKED_MEMSET

# GOTO
map GUARD_GOTO             GOTO_GUARD_POSIX
map GUARD_POSIX_GOTO       GOTO_GUARD_POSIX
map GUARD_NONNULL_GOTO     GOTO_GUARD_PTR
map GUARD_RESULT_GOTO      GOTO_GUARD_RESULT

# s2n_result
map GUARD_RESULT           RESULT_GUARD
map GUARD_AS_RESULT        RESULT_GUARD_POSIX
map GUARD_RESULT_PTR       RESULT_GUARD_PTR
map GUARD_RESULT_OSSL      RESULT_GUARD_OSSL
map ENSURE                 RESULT_ENSURE
map ENSURE_REF             RESULT_ENSURE_REF
map ENSURE_MUT             RESULT_ENSURE_MUT
map ENSURE_GTE             RESULT_ENSURE_GTE
map ENSURE_LTE             RESULT_ENSURE_LTE
map ENSURE_GT              RESULT_ENSURE_GT
map ENSURE_LT              RESULT_ENSURE_LT
map ENSURE_NE              RESULT_ENSURE_NE
map ENSURE_EQ              RESULT_ENSURE_EQ
map ENSURE_OK              RESULT_ENSURE_OK
map DEBUG_ENSURE           RESULT_DEBUG_ENSURE
map BAIL                   RESULT_BAIL
map CHECKED_MEMCPY         RESULT_CHECKED_MEMCPY
map CHECKED_MEMSET         RESULT_CHECKED_MEMSET

