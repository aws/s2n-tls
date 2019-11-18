CBMC Proof Infrastructure
=========================

This directory contains automated proofs of the memory safety of various parts
of the s2n codebase. A continuous integration system validates every
pull request posted to the repository against these proofs, and developers can
also run the proofs on their local machines.

The proofs are checked using the
[C Bounded Model Checker](http://www.cprover.org/cbmc/), an open-source static
analysis tool
([GitHub repository](https://github.com/diffblue/cbmc)). This README describes
how to run the proofs on your local clone of a:FR.


Prerequisites
-------------

You will need Python 3. On Windows, you will need Visual Studio 2015 or later
(in particular, you will need the Developer Command Prompt and NMake). On macOS
and Linux, you will need Make.


Installing CBMC
---------------

- Clone the [CBMC repository](https://github.com/diffblue/cbmc).

- The canonical compilation and installation instructions are in the
  [COMPILING.md](https://github.com/diffblue/cbmc/blob/develop/COMPILING.md)
  file in the CBMC repository; we reproduce the most important steps for
  Windows users here, but refer to that document if in doubt.
  - Download and install CMake from the [CMake website](https://cmake.org/download).
  - Download and install the "git for Windows" package, which also
    provides the `patch` command, from [here](https://git-scm.com/download/win).
  - Download the flex and bison for Windows package from
    [this sourceforge site](https://sourceforge.net/projects/winflexbison).
    "Install" it by dropping the contents of the entire unzipped
    package into the top-level CBMC source directory.
  - Change into the top-level CBMC source directory and run
    ```
    cmake -H. -Bbuild -DCMAKE_BUILD_TYPE=Release -DWITH_JBMC=OFF
    cmake --build build
    ```

- Ensure that you can run the programs `cbmc`, `goto-cc` (or `goto-cl`
  on Windows), and `goto-instrument` from the command line. If you build
  CBMC with CMake, the programs will have been installed under the
  `build/bin/Debug` directory under the top-level `cbmc` directory; you
  should add that directory to your `$PATH`. If you built CBMC using
  Make, then those programs will have been installed in the `src/cbmc`,
  `src/goto-cc`, and `src/goto-instrument` directories respectively.


Running the proofs
------------------

Each of the leaf directories under `proofs` is a proof of the memory
safety of a single entry point. The scripts that you ran in the
previous step will have left a Makefile in each of those directories. To
run a proof, change into the directory for that proof and run `make` on Linux or macOS. The proofs may take some time to run; they eventually write their output to `cbmc.txt`, which should have the text `VERIFICATION SUCCESSFUL` at the end.


Proof directory structure
-------------------------

This directory contains the following subdirectories:

- `proofs` contains the proofs run against each pull request
- `include` contains the `.h` files needed by proofs
- `source` contains functions useful in multiple CBMC proofs
- `stubs` contains stubs for functions which are modelled by CBMC
