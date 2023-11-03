+++
title = 'Debugging With GDB'
date = 2023-10-27T13:44:04-07:00
weight = 70
draft = false
+++

> [!NOTE]
> Could this be in the user guide?

When trying to debug a failing test case, it is often useful to use a debugger like `gdb`. First make sure that the tests and s2n are compiled with debug information. This can be done by setting the `CMAKE_BUILD_TYPE` to `DEBUG`. Alternatively, you can set the build type to `RelWithDebInfo` to get a release build with debug info included.

```sh
# generate the build configuration with debug symbols enabled
cmake . \
    -B build \
    -D CMAKE_BUILD_TYPE=DEBUG
```

Our unit tests rely on relative paths for certificates, so the test executable must be invoked from the folder that holds the test source file, or you can `cd` into the unit test folder once gdb is running.

To run the `s2n_x509_validator_test` with `gdb`

```sh
pwd
# .../s2n-tls/tests/unit/
gdb ../../build/bin/s2n_x509_validator_test
```
