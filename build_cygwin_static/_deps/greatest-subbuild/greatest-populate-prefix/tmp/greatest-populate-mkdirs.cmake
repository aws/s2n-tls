# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file LICENSE.rst or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/cygdrive/c/Users/samue/repos/auto-win-msvc/greatest")
  file(MAKE_DIRECTORY "/cygdrive/c/Users/samue/repos/auto-win-msvc/greatest")
endif()
file(MAKE_DIRECTORY
  "/cygdrive/c/Users/samue/repos/s2n-tls/build_cygwin_static/_deps/greatest-build"
  "/cygdrive/c/Users/samue/repos/s2n-tls/build_cygwin_static/_deps/greatest-subbuild/greatest-populate-prefix"
  "/cygdrive/c/Users/samue/repos/s2n-tls/build_cygwin_static/_deps/greatest-subbuild/greatest-populate-prefix/tmp"
  "/cygdrive/c/Users/samue/repos/s2n-tls/build_cygwin_static/_deps/greatest-subbuild/greatest-populate-prefix/src/greatest-populate-stamp"
  "/cygdrive/c/Users/samue/repos/s2n-tls/build_cygwin_static/_deps/greatest-subbuild/greatest-populate-prefix/src"
  "/cygdrive/c/Users/samue/repos/s2n-tls/build_cygwin_static/_deps/greatest-subbuild/greatest-populate-prefix/src/greatest-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/cygdrive/c/Users/samue/repos/s2n-tls/build_cygwin_static/_deps/greatest-subbuild/greatest-populate-prefix/src/greatest-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/cygdrive/c/Users/samue/repos/s2n-tls/build_cygwin_static/_deps/greatest-subbuild/greatest-populate-prefix/src/greatest-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
