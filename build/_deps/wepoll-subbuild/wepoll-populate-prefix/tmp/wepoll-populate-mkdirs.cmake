# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file LICENSE.rst or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "C:/Users/samue/repos/s2n-tls/build/_deps/wepoll-src")
  file(MAKE_DIRECTORY "C:/Users/samue/repos/s2n-tls/build/_deps/wepoll-src")
endif()
file(MAKE_DIRECTORY
  "C:/Users/samue/repos/s2n-tls/build/_deps/wepoll-build"
  "C:/Users/samue/repos/s2n-tls/build/_deps/wepoll-subbuild/wepoll-populate-prefix"
  "C:/Users/samue/repos/s2n-tls/build/_deps/wepoll-subbuild/wepoll-populate-prefix/tmp"
  "C:/Users/samue/repos/s2n-tls/build/_deps/wepoll-subbuild/wepoll-populate-prefix/src/wepoll-populate-stamp"
  "C:/Users/samue/repos/s2n-tls/build/_deps/wepoll-subbuild/wepoll-populate-prefix/src"
  "C:/Users/samue/repos/s2n-tls/build/_deps/wepoll-subbuild/wepoll-populate-prefix/src/wepoll-populate-stamp"
)

set(configSubDirs Debug)
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "C:/Users/samue/repos/s2n-tls/build/_deps/wepoll-subbuild/wepoll-populate-prefix/src/wepoll-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "C:/Users/samue/repos/s2n-tls/build/_deps/wepoll-subbuild/wepoll-populate-prefix/src/wepoll-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
