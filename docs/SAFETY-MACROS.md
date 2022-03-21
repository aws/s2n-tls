
[//]: # (DO NOT DIRECTLY MODIFY THIS FILE:)
[//]: # (The code in this file is generated from scripts/s2n_safety_macros.py and any modifications)
[//]: # (should be in there.)

# S2N Safety Macros

## Macros for functions that return `S2N_RESULT`


### RESULT_BAIL(error)

Sets the global `s2n_errno` to `error` and returns with an `S2N_RESULT_ERROR`


### RESULT_ENSURE(condition, error)

Ensures the `condition` is `true`, otherwise the function will `RESULT_BAIL` with `error`


### RESULT_DEBUG_ENSURE(condition, error)

Ensures the `condition` is `true`, otherwise the function will `RESULT_BAIL` with `error`

NOTE: The condition will _only_ be checked when the code is compiled in debug mode.
      In release mode, the check is removed.


### RESULT_ENSURE_OK(result, error)

Ensures `s2n_result_is_ok(result)`, otherwise the function will `RESULT_BAIL` with `error`

This can be useful for overriding the global `s2n_errno`


### RESULT_ENSURE_GTE(a, b)

Ensures `a` is greater than or equal to `b`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_SAFETY` error


### RESULT_ENSURE_LTE(a, b)

Ensures `a` is less than or equal to `b`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_SAFETY` error


### RESULT_ENSURE_GT(a, b)

Ensures `a` is greater than `b`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_SAFETY` error


### RESULT_ENSURE_LT(a, b)

Ensures `a` is less than `b`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_SAFETY` error


### RESULT_ENSURE_EQ(a, b)

Ensures `a` is equal to `b`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_SAFETY` error


### RESULT_ENSURE_NE(a, b)

Ensures `a` is not equal to `b`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_SAFETY` error


### RESULT_ENSURE_INCLUSIVE_RANGE(min, n, max)

Ensures `min <= n <= max`, otherwise the function will `RESULT_BAIL` with `S2N_ERR_SAFETY`


### RESULT_ENSURE_EXCLUSIVE_RANGE(min, n, max)

Ensures `min < n < max`, otherwise the function will `RESULT_BAIL` with `S2N_ERR_SAFETY`


### RESULT_ENSURE_REF(x)

Ensures `x` is a readable reference, otherwise the function will `RESULT_BAIL` with `S2N_ERR_NULL`


### RESULT_ENSURE_MUT(x)

Ensures `x` is a mutable reference, otherwise the function will `RESULT_BAIL` with `S2N_ERR_NULL`


### RESULT_PRECONDITION(result)

Ensures the `result` is `S2N_RESULT_OK`, otherwise the function will return an error signal

`RESULT_PRECONDITION` should be used at the beginning of a function to make assertions about
the provided arguments. By default, it is functionally equivalent to `RESULT_GUARD(result)`
but can be altered by a testing environment to provide additional guarantees.


### RESULT_POSTCONDITION(result)

Ensures the `result` is `S2N_RESULT_OK`, otherwise the function will return an error signal

NOTE: The condition will _only_ be checked when the code is compiled in debug mode.
      In release mode, the check is removed.

`RESULT_POSTCONDITION` should be used at the end of a function to make assertions about
the resulting state. In debug mode, it is functionally equivalent to `RESULT_GUARD(result)`.
In production builds, it becomes a no-op. This can also be altered by a testing environment
to provide additional guarantees.


### RESULT_CHECKED_MEMCPY(destination, source, len)

Performs a safer memcpy.

The following checks are performed:

* `destination` is non-null
* `source` is non-null

Callers will still need to ensure the following:

* The size of the data pointed to by both the `destination` and `source` parameters,
  shall be at least `len` bytes.


### RESULT_CHECKED_MEMSET(destination, value, len)

Performs a safer memset

The following checks are performed:

* `destination` is non-null

Callers will still need to ensure the following:

* The size of the data pointed to by the `destination` parameter shall be at least
  `len` bytes.


### RESULT_GUARD(result)

Ensures `s2n_result_is_ok(result)`, otherwise the function will return `S2N_RESULT_ERROR`


### RESULT_GUARD_OSSL(result, error)

Ensures `result == _OSSL_SUCCESS`, otherwise the function will `RESULT_BAIL` with `error`


### RESULT_GUARD_POSIX(result)

Ensures `(result) >= S2N_SUCCESS`, otherwise the function will return `S2N_RESULT_ERROR`


### RESULT_GUARD_PTR(result)

Ensures `(result) != NULL`, otherwise the function will return `S2N_RESULT_ERROR`

Does not set s2n_errno to S2N_ERR_NULL, so is NOT a direct replacement for RESULT_ENSURE_REF.


## Macros for functions that return `int` (POSIX error signal)


### POSIX_BAIL(error)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Sets the global `s2n_errno` to `error` and returns with an `S2N_FAILURE`


### POSIX_ENSURE(condition, error)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures the `condition` is `true`, otherwise the function will `POSIX_BAIL` with `error`


### POSIX_DEBUG_ENSURE(condition, error)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures the `condition` is `true`, otherwise the function will `POSIX_BAIL` with `error`

NOTE: The condition will _only_ be checked when the code is compiled in debug mode.
      In release mode, the check is removed.


### POSIX_ENSURE_OK(result, error)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `(result) >= S2N_SUCCESS`, otherwise the function will `POSIX_BAIL` with `error`

This can be useful for overriding the global `s2n_errno`


### POSIX_ENSURE_GTE(a, b)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `a` is greater than or equal to `b`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_SAFETY` error


### POSIX_ENSURE_LTE(a, b)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `a` is less than or equal to `b`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_SAFETY` error


### POSIX_ENSURE_GT(a, b)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `a` is greater than `b`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_SAFETY` error


### POSIX_ENSURE_LT(a, b)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `a` is less than `b`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_SAFETY` error


### POSIX_ENSURE_EQ(a, b)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `a` is equal to `b`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_SAFETY` error


### POSIX_ENSURE_NE(a, b)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `a` is not equal to `b`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_SAFETY` error


### POSIX_ENSURE_INCLUSIVE_RANGE(min, n, max)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `min <= n <= max`, otherwise the function will `POSIX_BAIL` with `S2N_ERR_SAFETY`


### POSIX_ENSURE_EXCLUSIVE_RANGE(min, n, max)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `min < n < max`, otherwise the function will `POSIX_BAIL` with `S2N_ERR_SAFETY`


### POSIX_ENSURE_REF(x)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `x` is a readable reference, otherwise the function will `POSIX_BAIL` with `S2N_ERR_NULL`


### POSIX_ENSURE_MUT(x)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `x` is a mutable reference, otherwise the function will `POSIX_BAIL` with `S2N_ERR_NULL`


### POSIX_PRECONDITION(result)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures the `result` is `S2N_RESULT_OK`, otherwise the function will return an error signal

`POSIX_PRECONDITION` should be used at the beginning of a function to make assertions about
the provided arguments. By default, it is functionally equivalent to `POSIX_GUARD_RESULT(result)`
but can be altered by a testing environment to provide additional guarantees.


### POSIX_POSTCONDITION(result)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures the `result` is `S2N_RESULT_OK`, otherwise the function will return an error signal

NOTE: The condition will _only_ be checked when the code is compiled in debug mode.
      In release mode, the check is removed.

`POSIX_POSTCONDITION` should be used at the end of a function to make assertions about
the resulting state. In debug mode, it is functionally equivalent to `POSIX_GUARD_RESULT(result)`.
In production builds, it becomes a no-op. This can also be altered by a testing environment
to provide additional guarantees.


### POSIX_CHECKED_MEMCPY(destination, source, len)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Performs a safer memcpy.

The following checks are performed:

* `destination` is non-null
* `source` is non-null

Callers will still need to ensure the following:

* The size of the data pointed to by both the `destination` and `source` parameters,
  shall be at least `len` bytes.


### POSIX_CHECKED_MEMSET(destination, value, len)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Performs a safer memset

The following checks are performed:

* `destination` is non-null

Callers will still need to ensure the following:

* The size of the data pointed to by the `destination` parameter shall be at least
  `len` bytes.


### POSIX_GUARD(result)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `(result) >= S2N_SUCCESS`, otherwise the function will return `S2N_FAILURE`


### POSIX_GUARD_OSSL(result, error)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `result == _OSSL_SUCCESS`, otherwise the function will `POSIX_BAIL` with `error`


### POSIX_GUARD_RESULT(result)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `s2n_result_is_ok(result)`, otherwise the function will return `S2N_FAILURE`


### POSIX_GUARD_PTR(result)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `(result) != NULL`, otherwise the function will return `S2N_FAILURE`

Does not set s2n_errno to S2N_ERR_NULL, so is NOT a direct replacement for POSIX_ENSURE_REF.


## Macros for functions that return a pointer


### PTR_BAIL(error)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Sets the global `s2n_errno` to `error` and returns with an `NULL`


### PTR_ENSURE(condition, error)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures the `condition` is `true`, otherwise the function will `PTR_BAIL` with `error`


### PTR_DEBUG_ENSURE(condition, error)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures the `condition` is `true`, otherwise the function will `PTR_BAIL` with `error`

NOTE: The condition will _only_ be checked when the code is compiled in debug mode.
      In release mode, the check is removed.


### PTR_ENSURE_OK(result, error)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `(result) != NULL`, otherwise the function will `PTR_BAIL` with `error`

This can be useful for overriding the global `s2n_errno`


### PTR_ENSURE_GTE(a, b)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `a` is greater than or equal to `b`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_SAFETY` error


### PTR_ENSURE_LTE(a, b)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `a` is less than or equal to `b`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_SAFETY` error


### PTR_ENSURE_GT(a, b)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `a` is greater than `b`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_SAFETY` error


### PTR_ENSURE_LT(a, b)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `a` is less than `b`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_SAFETY` error


### PTR_ENSURE_EQ(a, b)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `a` is equal to `b`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_SAFETY` error


### PTR_ENSURE_NE(a, b)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `a` is not equal to `b`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_SAFETY` error


### PTR_ENSURE_INCLUSIVE_RANGE(min, n, max)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `min <= n <= max`, otherwise the function will `PTR_BAIL` with `S2N_ERR_SAFETY`


### PTR_ENSURE_EXCLUSIVE_RANGE(min, n, max)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `min < n < max`, otherwise the function will `PTR_BAIL` with `S2N_ERR_SAFETY`


### PTR_ENSURE_REF(x)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `x` is a readable reference, otherwise the function will `PTR_BAIL` with `S2N_ERR_NULL`


### PTR_ENSURE_MUT(x)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `x` is a mutable reference, otherwise the function will `PTR_BAIL` with `S2N_ERR_NULL`


### PTR_PRECONDITION(result)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures the `result` is `S2N_RESULT_OK`, otherwise the function will return an error signal

`PTR_PRECONDITION` should be used at the beginning of a function to make assertions about
the provided arguments. By default, it is functionally equivalent to `PTR_GUARD_RESULT(result)`
but can be altered by a testing environment to provide additional guarantees.


### PTR_POSTCONDITION(result)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures the `result` is `S2N_RESULT_OK`, otherwise the function will return an error signal

NOTE: The condition will _only_ be checked when the code is compiled in debug mode.
      In release mode, the check is removed.

`PTR_POSTCONDITION` should be used at the end of a function to make assertions about
the resulting state. In debug mode, it is functionally equivalent to `PTR_GUARD_RESULT(result)`.
In production builds, it becomes a no-op. This can also be altered by a testing environment
to provide additional guarantees.


### PTR_CHECKED_MEMCPY(destination, source, len)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Performs a safer memcpy.

The following checks are performed:

* `destination` is non-null
* `source` is non-null

Callers will still need to ensure the following:

* The size of the data pointed to by both the `destination` and `source` parameters,
  shall be at least `len` bytes.


### PTR_CHECKED_MEMSET(destination, value, len)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Performs a safer memset

The following checks are performed:

* `destination` is non-null

Callers will still need to ensure the following:

* The size of the data pointed to by the `destination` parameter shall be at least
  `len` bytes.


### PTR_GUARD(result)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `(result) != NULL`, otherwise the function will return `NULL`


### PTR_GUARD_OSSL(result, error)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `result == _OSSL_SUCCESS`, otherwise the function will `PTR_BAIL` with `error`


### PTR_GUARD_RESULT(result)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `s2n_result_is_ok(result)`, otherwise the function will return `NULL`


### PTR_GUARD_POSIX(result)

DEPRECATED: all methods (except those in s2n.h) should return s2n_result.

Ensures `(result) >= S2N_SUCCESS`, otherwise the function will return `NULL`

