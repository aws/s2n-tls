# This file is configured by CMake automatically as CTestScript.cmake
# If you choose not to use CMake, this file may be hand configured, by
# filling in the required variables.

cmake_minimum_required(VERSION 4.3.3)

# CTest Start Step
set(CTEST_SOURCE_DIRECTORY "C:/Users/samue/repos/s2n-tls")
set(CTEST_BINARY_DIRECTORY "C:/Users/samue/repos/s2n-tls/build_msvc2022_shared")

# CTest Update Step
set(CTEST_UPDATE_COMMAND "C:/Program Files/Git/cmd/git.exe")
set(CTEST_UPDATE_OPTIONS "")
set(CTEST_UPDATE_VERSION_ONLY "")
set(CTEST_NIGHTLY_START_TIME "00:00:00 EDT")

# CVS options
set(CTEST_CVS_COMMAND "")
set(CTEST_CVS_UPDATE_OPTIONS "")

# Subversion options
set(CTEST_SVN_COMMAND "")
set(CTEST_SVN_OPTIONS "")
set(CTEST_SVN_UPDATE_OPTIONS "")

# Git options
set(CTEST_GIT_COMMAND "C:/Program Files/Git/cmd/git.exe")
set(CTEST_GIT_INIT_SUBMODULES "")
set(CTEST_GIT_UPDATE_CUSTOM "")
set(CTEST_GIT_UPDATE_OPTIONS "")

# Perforce options
set(CTEST_P4_COMMAND "")
set(CTEST_P4_CLIENT "")
set(CTEST_P4_OPTIONS "")
set(CTEST_P4_UPDATE_CUSTOM "")
set(CTEST_P4_UPDATE_OPTIONS "")

# CTest Configure Step
set(CTEST_CMAKE_GENERATOR "Visual Studio 17 2022")
set(CTEST_LABELS_FOR_SUBPROJECTS "")

# CTest Build Step
set(CTEST_CONFIGURATION_TYPE "Release")
set(CTEST_USE_LAUNCHERS "0")

# CTest Test Step
set(CTEST_RESOURCE_SPEC_FILE "")
set(CTEST_TEST_LOAD "")
set(CTEST_TEST_TIMEOUT "1500")

# CTest Coverage Step
set(CTEST_COVERAGE_COMMAND "COVERAGE_COMMAND-NOTFOUND")
set(CTEST_COVERAGE_EXTRA_FLAGS "-l")

# CTest MemCheck Step
set(CTEST_MEMORYCHECK_COMMAND "MEMORYCHECK_COMMAND-NOTFOUND")
set(CTEST_MEMORYCHECK_COMMAND_OPTIONS "         --leak-check=full         --leak-resolution=high         --trace-children=yes         -q --error-exitcode=123         --error-limit=no         --num-callers=40         --undef-value-errors=no         --track-fds=yes         --log-fd=2         --suppressions=valgrind.suppressions --run-libc-freeres=no")
set(CTEST_MEMORYCHECK_TYPE "Valgrind")
set(CTEST_MEMORYCHECK_SANITIZER_OPTIONS "")
set(CTEST_MEMORYCHECK_SUPPRESSIONS_FILE "")

# CTest Submit Step
set(CTEST_SITE "alien52")
set(CTEST_BUILD_NAME "Win32-MSBuild")
set(CTEST_SUBMIT_URL "http://")
set(CTEST_SUBMIT_INACTIVITY_TIMEOUT "")
set(CTEST_TLS_VERIFY "")
set(CTEST_TLS_VERSION "")

################################################################################

if(NOT MODEL)
  set(MODEL "Experimental")
endif()

if(MODEL STREQUAL "NightlyMemoryCheck")
  set(MODEL "Nightly")
  set(ACTIONS "Start;Update;Configure;Build;MemCheck;Coverage;Submit")
endif()

if(NOT ACTIONS)
  if(MODEL STREQUAL "Experimental")
    set(ACTIONS "Start;Configure;Build;Test;Coverage;Submit")
  else()
    set(ACTIONS "Start;Update;Configure;Build;Test;Coverage;Submit")
  endif()
endif()

################################################################################

set(_exit_code 0)

if("Start" IN_LIST ACTIONS OR NOT EXISTS "${CTEST_BINARY_DIRECTORY}/Testing/TAG")
  ctest_start("${MODEL}")
else()
  ctest_start("${MODEL}" APPEND)
endif()

if("Update" IN_LIST ACTIONS)
  ctest_update(RETURN_VALUE update_count)
  if(update_count LESS 0)
    math(EXPR _exit_code "${_exit_code} | 0x01")
  endif()
  if(MODEL STREQUAL "Continuous" AND update_count EQUAL 0)
    return()
  endif()
endif()

if("Configure" IN_LIST ACTIONS)
  ctest_configure(RETURN_VALUE success)
  if(success LESS 0)
    math(EXPR _exit_code "${_exit_code} | 0x02")
  endif()
endif()

if("Build" IN_LIST ACTIONS)
  ctest_read_custom_files("${CTEST_BINARY_DIRECTORY}")
  ctest_build(RETURN_VALUE success)
  if(NOT success EQUAL 0)
    math(EXPR _exit_code "${_exit_code} | 0x04")
  endif()
endif()

if("Test" IN_LIST ACTIONS)
  ctest_read_custom_files("${CTEST_BINARY_DIRECTORY}")
  ctest_test(RETURN_VALUE success)
  if(NOT success EQUAL 0)
    math(EXPR _exit_code "${_exit_code} | 0x08")
  endif()
endif()

if("Coverage" IN_LIST ACTIONS)
  ctest_read_custom_files("${CTEST_BINARY_DIRECTORY}")
  ctest_coverage(RETURN_VALUE success)
  if(NOT success EQUAL 0)
    math(EXPR _exit_code "${_exit_code} | 0x20")
  endif()
endif()

if("MemCheck" IN_LIST ACTIONS)
  ctest_read_custom_files("${CTEST_BINARY_DIRECTORY}")
  ctest_memcheck(RETURN_VALUE success)
  if(NOT success EQUAL 0)
    math(EXPR _exit_code "${_exit_code} | 0x10")
  endif()
endif()

file(GLOB notes_files LIST_DIRECTORIES OFF
  "${CTEST_BINARY_DIRECTORY}/Testing/Notes/*")
if(notes_files)
  list(APPEND CTEST_NOTES_FILES "${notes_files}")
endif()

if("Submit" IN_LIST ACTIONS)
  ctest_read_custom_files("${CTEST_BINARY_DIRECTORY}")
  ctest_submit(
    RETRY_COUNT "3"
    RETRY_DELAY "5"
    RETURN_VALUE success
    )
  if(NOT success EQUAL 0)
    math(EXPR _exit_code "${_exit_code} | 0x40")
  endif()
endif()

cmake_language(EXIT "${_exit_code}")
