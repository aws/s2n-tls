# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file LICENSE.rst or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "C:/Users/samue/repos/auto-win-msvc/greatest")
  file(MAKE_DIRECTORY "C:/Users/samue/repos/auto-win-msvc/greatest")
endif()
file(MAKE_DIRECTORY
  "C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/greatest-build"
  "C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/greatest-subbuild/greatest-populate-prefix"
  "C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/greatest-subbuild/greatest-populate-prefix/tmp"
  "C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/greatest-subbuild/greatest-populate-prefix/src/greatest-populate-stamp"
  "C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/greatest-subbuild/greatest-populate-prefix/src"
  "C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/greatest-subbuild/greatest-populate-prefix/src/greatest-populate-stamp"
)

set(configSubDirs Debug)
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/greatest-subbuild/greatest-populate-prefix/src/greatest-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/greatest-subbuild/greatest-populate-prefix/src/greatest-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
