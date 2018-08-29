# Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

set(CTEST_BUILD_TARGET fuzz)

include(CTest)
include(S2nSanitizers)

option(ENABLE_FUZZ_TESTS "Build and run fuzz tests" OFF)
set(FUZZ_TESTS_MAX_TIME 120 CACHE STRING "Max time to run each fuzz test")

# Adds fuzz tests to ctest
# Options:
#  fuzz_files: The list of fuzz test files
#  other_files: Other files to link into each fuzz test
function(s2n_add_fuzz_tests fuzz_files other_files)
    if(ENABLE_FUZZ_TESTS)
        if(NOT ENABLE_SANITIZERS)
            message(FATAL_ERROR "ENABLE_FUZZ_TESTS is set but ENABLE_SANITIZERS is set to OFF")
        endif()

        s2n_check_sanitizer(fuzzer)
        if (NOT HAS_SANITIZER_fuzzer)
            message(FATAL_ERROR "ENABLE_FUZZ_TESTS is set but the current compiler (${CMAKE_CXX_COMPILER_ID}) doesn't support -fsanitize=fuzzer")
        endif()

        file(GLOB OVERRIDE_SRC "tests/fuzz/LD_PRELOAD/*.c")

        foreach(override ${OVERRIDE_SRC})
            get_filename_component(OVERRIDE_FILE_NAME ${override} NAME_WE)
            add_library(${OVERRIDE_FILE_NAME} SHARED ${override})
            s2n_set_common_properties(${OVERRIDE_FILE_NAME})
            target_link_libraries(${OVERRIDE_FILE_NAME} s2n)
        endforeach()

        file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/corpus DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
        foreach(test_file ${fuzz_files})
            get_filename_component(TEST_FILE_NAME ${test_file} NAME_WE)

            set(FUZZ_BINARY_NAME ${TEST_FILE_NAME})
            add_executable(${FUZZ_BINARY_NAME} ${test_file} ${other_files})
            target_link_libraries(${FUZZ_BINARY_NAME} PRIVATE ${TEST_S2N_TARGET} PRIVATE testss2n PRIVATE m pthread)
            target_include_directories(${FUZZ_BINARY_NAME} PRIVATE api)
            target_include_directories(${FUZZ_BINARY_NAME} PRIVATE ./)
            target_include_directories(${FUZZ_BINARY_NAME} PRIVATE tests)
            s2n_set_common_properties(${FUZZ_BINARY_NAME})
            s2n_add_sanitizers(${FUZZ_BINARY_NAME} SANITIZERS "${${TEST_S2N_TARGET}_SANITIZERS};fuzzer")
            target_include_directories(${FUZZ_BINARY_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR})

            add_test(NAME ${TEST_FILE_NAME} COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/runFuzzTest_out_of_source.sh ${TEST_FILE_NAME} ${FUZZ_TESTS_MAX_TIME}
                    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

        endforeach()
    endif()
endfunction()