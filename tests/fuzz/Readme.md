# Fuzz Tests
By default, every test in this directory will be run as a fuzz test for several minutes each during builds. To run all fuzz tests simply run `make fuzz` from the top `s2n` directory to compile s2n with the proper flags and run the fuzz tests. To run a specific subset of fuzz tests, simply set the FUZZ_TESTS variable as follows:

> FUZZ_TESTS="test1 test2 test3"

#### Each Fuzz Test should conform to the following rules:
1. End in either `*_test.c` or `*_negative_test.c`.
    1. If the test ends with `*_test.c`, it is expected to pass fuzzing and return 0 (hereafter referred to as a "Positive test")
    2. If the test ends with `*_negative_test.c` the test is expected to fail in some way or return a non-zero integer (hereafter referred to as a "Negative test").
2. Strive to be deterministic (Eg. shouldn't depend on the time or on the output of a RNG). Each test should either always pass if a Positive Test, or always fail if a Negative Test.
3. If a Positive Fuzz test, it should have a non-empty corpus directory with inputs that have a relatively high branch coverage.
4. Have a function `int s2n_fuzz_init(int *argc, char **argv[])` that will perform any initialization that will be run only once at startup.
5. Have a function `int s2n_fuzz_test(const uint8_t *buf, size_t len)` that will pass `buf` to one of s2n's API's
5. Optionally add a function `void s2n_fuzz_cleanup()` which cleans up any global state.
6. Call `S2N_FUZZ_TARGET(s2n_fuzz_init, s2n_fuzz_test, s2n_fuzz_cleanup)` at the bottom of the test to initialize the fuzz target

## Fuzz Test Coverage
To generate coverage reports for fuzz tests, simply set the FUZZ_COVERAGE environment variable to any non-null value and run `make fuzz`. This will report the target function coverage and overall S2N coverage when running the tests. In order to define target functions for a fuzz test, simply add the following line to your fuzz test below the copyright notice:

> /* Target Functions: function1 function2 function3 */

As the tests run, more detailed coverage reports are placed in the following directory:

> s2n/coverage/fuzz

Each test outputs an HTML file which displays line by line coverage statistics and a .txt report which gives per-function coverage statistics in human-readable ASCII. After all fuzz tests have ran, a matching pair of coverage reports is generated for the total coverage of S2N by the entire set of tests performed.

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

# LD_PRELOAD
The `LD_PRELOAD` directory contains function overrides for each Fuzz test that will be used **instead** of the original functions defined elsewhere. These function overrides will only be used during fuzz tests, and will not effect the rest of the s2n codebase when not fuzzing. Using `LD_PRELOAD` instead of C Preprocessor `#ifdef`'s is preferable in the following ways:

1. Using the C Preprocessor requires the use of fuzz only compiler flags and `#ifdef`'s that end up cluttering the original s2n codebase and increases developer cognitive load when developing other features for s2n. Using `LD_PRELOAD` helps keep s2n's code clean, and reduces developer cognitive load when working with the core codebase.
2. `LD_PRELOAD` provides better flexibility than `#ifdef`'s in that it allows different Fuzz tests to efficiently have different function overrides for the same functions.
3. It is possible to override functions that are outside of s2n's codebase.

Each Fuzz test will have up to two `LD_PRELOAD` function override files used:

1. A test specific `${TEST_NAME}_overrides.c` file that contains overrides specific to that test.
2. `global_overrides.c` file that contains overrides that will be used in every fuzz test.
