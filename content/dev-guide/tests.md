+++
title = 'Tests'
date = 2023-10-27T13:44:04-07:00
weight = 60
draft = false
+++

s2n-tls is written in C99, a language which lacks a "standard" testing framework. Although there are some more well used C++ testing frameworks, s2n-tls also targets some embedded platforms on which a C++ compiler is unavailable.

Since testing and test-cases are absolutely mandatory for all s2n-tls functionality, s2n-tls includes its own small testing framework, defined in [tests/s2n_test.h](https://github.com/aws/s2n-tls/blob/main/tests/s2n_test.h). The framework consists of 15 macros that allow you to start a test suite, which is a normal C application with a main() function, and to validate various expectations.

Unit tests are added as .c files in [tests/unit/](https://github.com/aws/s2n-tls/blob/main/tests/unit/). A simple example to look at is [tests/unit/s2n_stuffer_base64_test.c](https://github.com/aws/s2n-tls/blob/main/tests/unit/s2n_stuffer_base64_test.c). The tests are started with BEGIN_TEST(), and expectations are tested with EXPECT_SUCCESS and EXPECT_EQUAL before exiting with an END_TEST call.

The test framework will take care of compiling and executing the tests and indicates success or failure with green or red text in the console.

In addition to fully covering functionality in the correct cases, s2n-tls tests are also expected to include adversarial or "negative" test cases. For example, the tests performed on record encryption validate that s2n-tls is tamper resistant by attempting to actually tamper with records. Similarly, we validate that our memory handling routines cannot be over-filled by attempting to over-fill them.

To avoid adding unneeded code to the production build of s2n-tls, there is also a small test library defined at [tests/testlib/](https://github.com/aws/s2n-tls/blob/main/tests/testlib/) which includes routines useful for test cases. For example, there is a hex parser and emitter, which is useful for defining network data in test cases, but not needed in production.

Unit tests are run automatically with `make`. To run a subset of the unit tests, set the `UNIT_TESTS` environment variable with the unit test name(s). For example:

```sh
UNIT_TESTS=s2n_hash_test make
```


