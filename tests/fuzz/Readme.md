# Fuzz Tests
By default, every test in this directory will be run as a fuzz test for several minutes each during builds. To run all fuzz tests, run the following commands from the top `s2n-tls` directory:
1. Compile with S2N_FUZZ_TEST option enabled
```
cmake . -Bbuild \
-DS2N_FUZZ_TEST=on
```
2. Compile the project
```
cmake --build ./build -- -j $(nproc)
```
3. Run fuzz tests
```
cmake --build build/ --target test -- ARGS="-L fuzz --output-on-failure"
```

To run a specific fuzz test, pass in the name of the test using the following command:
```
cmake --build build/ --target test -- ARGS="-L fuzz -R <TEST_NAME> --output-on-failure"
```
For example,
```
cmake --build build/ --target test -- ARGS="-L fuzz -R s2n_client_fuzz_test --output-on-failure"
```

#### Each Fuzz Test should conform to the following rules:
1. End in either `*_test.c` or `*_negative_test.c`.
    1. If the test ends with `*_test.c`, it is expected to pass fuzzing and return 0 (hereafter referred to as a "Positive test")
    2. If the test ends with `*_negative_test.c` the test is expected to fail in some way or return a non-zero integer (hereafter referred to as a "Negative test").
2. Strive to be deterministic (Eg. shouldn't depend on the time or on the output of a RNG). Each test should either always pass if a Positive Test, or always fail if a Negative Test.
3. If a Positive Fuzz test, it should have a non-empty corpus directory with inputs that have a relatively high branch coverage.
4. If a Positive Fuzz test, define target functions for the test by adding following lines to your test below the copyright notice:
> /* Target Functions: function1 function2 function3 */
5. Have a function `int s2n_fuzz_init(int *argc, char **argv[])` that will perform any initialization that will be run only once at startup.
6. Have a function `int s2n_fuzz_test(const uint8_t *buf, size_t len)` that will pass `buf` to one of s2n's API's
7. Optionally add a function `void s2n_fuzz_cleanup()` which cleans up any global state.
8. Call `S2N_FUZZ_TARGET(s2n_fuzz_init, s2n_fuzz_test, s2n_fuzz_cleanup)` at the bottom of the test to initialize the fuzz target

## Fuzz Test Coverage
To generate coverage reports for fuzz tests, s2n-tls needs to be compiled with the following options:
```
cmake . -Bbuild \
-DCMAKE_PREFIX_PATH=/usr/local/$S2N_LIBCRYPTO \
-DS2N_FUZZ_TEST=on \
-DCOVERAGE=on \
-DBUILD_SHARED_LIBS=on

cmake --build ./build -- -j $(nproc)
```

If you see an error that says `This project requires clang for coverage support. You are currently using X`, set the C compiler environment variable to use Clang:
```
export CC=/usr/bin/clang
export CXX=/usr/bin/clang++
```

Next, run fuzz tests. This will generate `.info` files for each fuzz test containing coverage information. 
```
cmake --build build/ --target test -- ARGS="-L fuzz --output-on-failure"
```

The `.info` files contain raw coverage data.  To convert them into HTML format, run the following script from the root of s2n-tls. This generates HTML files showing line-by-line coverage statistics for each fuzz test, as well as total coverage report for s2n-tls across all tests.
```
./codebuild/bin/fuzz_coverage_report.sh
```

You will see coverage reports placed in the following directory:
> s2n-tls/tests/fuzz/coverage

## Fuzz Test Directory Structure
For a test with name `$TEST_NAME`, its files should be laid out with the following structure:

**Required:** The actual Fuzz test to run:
> `s2n/tests/fuzz/${TEST_NAME}.c`

**Required:** The Corpus directory with inputs that provide good branch coverage:
> `s2n/tests/fuzz/corpus/${TEST_NAME}/*`

**Optional:** Any `LD_PRELOAD` function overrides:
> `s2n/tests/fuzz/LD_PRELOAD/${TEST_NAME}_overrides.c`

# Corpus
A Corpus is a directory of "interesting" inputs that result in a good branch/code coverage. These inputs will be permuted in random ways and checked to see if this permutation results in greater branch coverage or in a failure (Segfault, Memory Leak, Buffer Overflow, Non-zero return code, etc). If the permutation results in greater branch coverage, then it will be added to the Corpus directory. If a Memory leak or a Crash is detected, that file will **not** be added to the corpus for that test, and will instead be written to the current directory (`s2n/tests/fuzz/crash-*` or `s2n/tests/fuzz/leak-*`). These files will be automatically deleted for any Negative Fuzz tests that are expected to crash or leak memory so as to not clutter the directory.

To continuously improve corpus inputs, we have a scheduled job that runs every day for approximately 8 hours. These tests begin with corpus files stored in an S3 bucket. At the end of each run, the existing corpus files are replaced with updated ones, potentially increasing branch coverage over time. This process allows for gradual and automated enhancement of the corpus.

To enable this, two environment variables must be defined: `CORPUS_UPLOAD_LOC` and `ARTIFACT_UPLOAD_LOC`. `CORPUS_UPLOAD_LOC` specifies where corpus files are stored, while `ARTIFACT_UPLOAD_LOC`defines where output logs from fuzzing are saved, which can be used for debugging if a new bug is detected during fuzzing.

# LD_PRELOAD
The `LD_PRELOAD` directory contains function overrides for each Fuzz test that will be used **instead** of the original functions defined elsewhere. These function overrides will only be used during fuzz tests, and will not effect the rest of the s2n codebase when not fuzzing. Using `LD_PRELOAD` instead of C Preprocessor `#ifdef`'s is preferable in the following ways:

1. Using the C Preprocessor requires the use of fuzz only compiler flags and `#ifdef`'s that end up cluttering the original s2n codebase and increases developer cognitive load when developing other features for s2n. Using `LD_PRELOAD` helps keep s2n's code clean, and reduces developer cognitive load when working with the core codebase.
2. `LD_PRELOAD` provides better flexibility than `#ifdef`'s in that it allows different Fuzz tests to efficiently have different function overrides for the same functions.
3. It is possible to override functions that are outside of s2n's codebase.

Each Fuzz test will have up to two `LD_PRELOAD` function override files used:

1. A test specific `${TEST_NAME}_overrides.c` file that contains overrides specific to that test.
2. `global_overrides.c` file that contains overrides that will be used in every fuzz test.
