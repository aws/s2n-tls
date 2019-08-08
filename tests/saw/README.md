# SAW tests for s2n

This repository contains specifications of the various parts of the HMAC
algorithm used in TLS along with SAW scripts to prove the s2n implementation of
this algorithm equivalent to the spec.


## The tests

Currently this directory houses a test that compares the s2n
implementation of HMAC with a cryptol spec of the same. There are 3
files that take part in this test.

  1. bitcode/all_llvm.bc
  2. spec/HMAC.cry
  3. spec/HMAC.saw

all_llvm.bc contains linked llvm bitcode definitions for the entirity
of s2n/crypto. This bitcode is not currently linked with code from the
other directories in s2n, because so far, those directories have not
contained code necessary for verification.

HMAC.cry is a [Cryptol](http://www.cryptol.net/)
specification/implementation of HMAC. Cryptol can be seen as an
implementation because it is executable. It can be given a message and
a key as input, and produce output. It is a specification because the
cryptol language looks like the mathematical language that
cryptographers like to specify cryptograpy in. It does not have many
of the safety risks that a C program has, and it is typically much
easier to read and understand than a C program.

HMAC.saw is a [SAWScript](https://github.com/GaloisInc/saw-script)
file that defines the relationship between the previous two files. It
defines an equivalence between the HMAC functions that live in
all_llvm.bc and the HMAC functions that are in HMAC.cry. It then gives
instructions for how automated solvers can be used to prove this
equivalence. When run with the command `saw HMAC.saw`, this file loads
in the other two and proves the HMAC files equivalent.

## The build

Running the saw tests will require a SAW executable, which must be able
to find the Yices and Z3 provers on the path. Future examples might
require further installation of provers. The build will also require
clang, which is not currently a necessary prerequisite for s2n.

We have integrated the build of this test into the s2n build. Right
now, the steps for a build are (files that do the work are listed in parenthesis):

  1. patch s2n to prepare it for SAW, when necessary (currently not
     necessary) (s2n/Makefile)
  2. compile all files in s2n/crypto to llvm bitcode (located in
     s2n/tests/saw/bitcode) using the clang
     compiler, (s2n/crypto/Makefile, sn2/s2n.mk)
  3. link the files in s2n/tests/saw/bitcode into all_llvm.bc using
     llvm-link (s2n/crypto/Makefile)
  4. enter the test directory and run all of the saw scripts that are
     in the s2n/tests/saw directory, checking and logging the results
     (s2n/Makefile, s2n/tests/makefile, s2n/tests/saw) and
  5. enable cleaning for compiled bitcode and test logs. all bitcode
     (.bc) in any source directories will be cleaned, but logs (.log)
     will only be cleaned out of the saw directory. On recommendation,
     it's trivial to switch the behavior for either.
     (s2n/tests/Makefile, s2n/tests/saw)

With the exception of step 5 (`make clean`), all of these steps are run
by running `make saw` in the s2n root directory. The only modification
needed for a Travis script is to install Yices and Z3, download SAW, and
run the SAW make target.
