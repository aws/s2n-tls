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

include(CheckCCompilerFlag)
include(CheckIncludeFile)

# This function will set all common flags on a target
# Options:
#  NO_WGNU: Disable -Wgnu
#  NO_WEXTRA: Disable -Wextra
#  NO_PEDANTIC: Disable -pedantic
function(s2n_set_common_properties target)
    set(options NO_WGNU NO_WEXTRA NO_PEDANTIC)
    cmake_parse_arguments(SET_PROPERTIES "${options}" "" "" ${ARGN})

    if(MSVC)
        list(APPEND S2N_C_FLAGS /W4 /WX)
    else()
        list(APPEND S2N_C_FLAGS -pedantic -std=c99 -Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts
                -Wuninitialized -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings -Wno-deprecated-declarations
                -Wno-unknown-pragmas -Wformat-security)
        list(APPEND S2N_PUBLIC_C_FLAGS -fPIC)

        if(NOT SET_PROPERTIES_NO_WEXTRA)
            list(APPEND S2N_C_FLAGS -Wextra)
        endif()

        if(NOT SET_PROPERTIES_NO_PEDANTIC)
            list(APPEND S2N_C_FLAGS -pedantic)
        endif()

        list(APPEND S2N_C_DEFINES -D_POSIX_C_SOURCE=200809L)

        # Warning disables always go last to avoid future flags re-enabling them
        list(APPEND S2N_C_FLAGS -Wno-long-long)
    endif()

    if(NOT SET_PROPERTIES_NO_WGNU)
        check_c_compiler_flag(-Wgnu HAS_WGNU)
        if(HAS_WGNU)
            # -Wgnu-zero-variadic-macro-arguments results in a lot of false positives
            list(APPEND S2N_C_FLAGS -Wgnu -Wno-gnu-zero-variadic-macro-arguments)
        endif()
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "" OR CMAKE_BUILD_TYPE MATCHES Debug)
        list(APPEND S2N_C_DEFINES -DDEBUG_BUILD)
    else()
        list(APPEND S2N_C_DEFINES -D_FORTIFY_SOURCE=2)
    endif()

    if(NOT NO_STACK_PROTECTOR)
        target_compile_options(${target} PRIVATE -Wstack-protector -fstack-protector-all)
    endif()

    target_compile_options(${target} PRIVATE ${S2N_C_FLAGS})
    target_compile_options(${target} PUBLIC ${S2N_PUBLIC_C_FLAGS})
    target_compile_definitions(${target} PRIVATE ${S2N_C_DEFINES})

    set_target_properties(${target} PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
endfunction()