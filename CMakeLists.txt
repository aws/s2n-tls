cmake_minimum_required (VERSION 3.0)
project(s2n C)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(INSTALL_LIB_DIR lib CACHE PATH "Installaction directory for libraries")
set(INSTALL_INCLUDE_DIR include CACHE PATH "installaction directory for header files")
set(INSTALL_CMAKE_DIR lib/cmake CACHE PATH "Installation directory for cmake files")

set(CMAKE_C_FLAGS_DEBUGOPT "")
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(BUILD_FOR_FUZZ_TESTING "The build is exclusively for fuzz tests. No unit or integration tests will
                               be built or run if this option is turned on." OFF)
option(RUN_INTEGRATION_TESTS  "Runs integration tests as part of the test target. To use this option, you also need to set
                               the S2ND_HOST, S2ND_PORT, and S2N_LIB_CRYPTO arguments." OFF)
set(S2ND_HOST 127.0.0.1 CACHE STRING  "Host to use for s2nd tests.")
set(S2ND_PORT 88888 CACHE STRING  "Port to use for s2nd tests.")
set(S2N_LIBCRYPTO openssl-1.1.0 CACHE STRING "openssl version to test against.")
option(RUN_UNIT_TESTS "Runs unit tests as part of the build." ON)

include(S2nCFlags)
include(S2nSanitizers)

##header files
file(GLOB API_HEADERS
     "api/*.h"
)

file(GLOB CRYPTO_HEADERS
    "crypto/*.h"
)

file(GLOB ERROR_HEADERS
    "error/*.h"
)

file(GLOB STUFFER_HEADERS
    "stuffer/*.h"
)

file(GLOB TLS_HEADERS
    "tls/*.h"
)

file(GLOB UTILS_HEADERS
    "utils/*.h"
)

 ##source files
 file(GLOB CRYPTO_SRC
     "crypto/*.c"
 )

file(GLOB ERROR_SRC
    "error/*.c"
)

file(GLOB STUFFER_SRC
    "stuffer/*.c"
)

file(GLOB TLS_SRC
    "tls/*.c"
)

file(GLOB UTILS_SRC
    "utils/*.c"
)

include(S2nLibFuzzer)

if (BUILD_FOR_FUZZ_TESTING)
    set(BUILD_SHARED_LIBS ON)
    set(ENABLE_FUZZ_TESTS ON)
    set(ENABLE_SANITIZERS ON)
endif()

##be nice to visual studio users
if(MSVC)
    source_group("Header Files\\s2n\\api" FILES ${API_HEADERS})
    source_group("Header Files\\s2n\\crypto" FILES ${CRYPTO_HEADERS})
    source_group("Header Files\\s2n\\error" FILES ${ERROR_HEADERS})
    source_group("Header Files\\s2n\\stuffer" FILES ${STUFFER_HEADERS})
    source_group("Header Files\\s2n\\tls" FILES ${TLS_HEADERS})
    source_group("Header Files\\s2n\\utils" FILES ${UTILS_HEADERS})

    source_group("Source Files\\crypto" FILES ${CRYPTO_SRC})
    source_group("Source Files\\error" FILES ${ERROR_SRC})
    source_group("Source Files\\stuffer" FILES ${STUFFER_SRC})
    source_group("Source Files\\tls" FILES ${TLS_SRC})
    source_group("Source Files\\utils" FILES ${UTILS_SRC})
endif()

if(APPLE)
    set(OS_LIBS c pthread)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    set(OS_LIBS thr)
elseif(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
    set(OS_LIBS pthread)
else()
    set(OS_LIBS pthread dl rt)
endif()

file(GLOB S2N_HEADERS
    ${API_HEADERS}
    ${CRYPTO_HEADERS}
    ${ERROR_HEADERS}
    ${STUFFER_HEADERS}
    ${TLS_HEADERS}
    ${UTILS_HEADERS}
 )

 file(GLOB S2N_SRC
    ${CRYPTO_SRC}
    ${ERROR_SRC}
    ${STUFFER_SRC}
    ${TLS_SRC}
    ${UTILS_SRC}
 )

find_package(LibCrypto REQUIRED)
add_library(${CMAKE_PROJECT_NAME} ${S2N_HEADERS} ${S2N_SRC})

s2n_set_common_properties(${CMAKE_PROJECT_NAME} NO_WEXTRA)
s2n_add_sanitizers(${CMAKE_PROJECT_NAME} BLACKLIST "sanitizer-blacklist.txt")

find_package(LibCrypto REQUIRED)
target_link_libraries(s2n PRIVATE LibCrypto::Crypto PRIVATE ${OS_LIBS})

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/api> $<INSTALL_INTERFACE:include>)
target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC $<TARGET_PROPERTY:LibCrypto::Crypto,INTERFACE_INCLUDE_DIRECTORIES>)

s2n_set_common_properties(${CMAKE_PROJECT_NAME} NO_WEXTRA)
s2n_add_sanitizers(${CMAKE_PROJECT_NAME} BLACKLIST "sanitizer-blacklist.txt")

if (NOT BUILD_SHARED_LIBS)
    message("Since s2n needs dynamic links for LD_PRELOAD overrides, we still have to build in shared mode for testing.")
    set(TEST_S2N_TARGET s2n_shared)
    add_library(${TEST_S2N_TARGET} SHARED ${S2N_HEADERS} ${S2N_SRC})
    s2n_set_common_properties(${TEST_S2N_TARGET} NO_WEXTRA)
    s2n_add_sanitizers(${TEST_S2N_TARGET} BLACKLIST "sanitizer-blacklist.txt")

    find_package(LibCrypto REQUIRED)
    target_link_libraries(${TEST_S2N_TARGET} PRIVATE LibCrypto::Crypto PRIVATE ${OS_LIBS})

    target_include_directories(${TEST_S2N_TARGET} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
    target_include_directories(${TEST_S2N_TARGET} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/api> $<INSTALL_INTERFACE:include>)
    target_include_directories(${TEST_S2N_TARGET} PUBLIC $<TARGET_PROPERTY:LibCrypto::Crypto,INTERFACE_INCLUDE_DIRECTORIES>)

    s2n_set_common_properties(${TEST_S2N_TARGET} NO_WEXTRA)
    s2n_add_sanitizers(${TEST_S2N_TARGET} BLACKLIST "sanitizer-blacklist.txt")
else()
    set(TEST_S2N_TARGET s2n)
endif()

if (ENABLE_FUZZ_TESTS)
    s2n_add_sanitizers(${TEST_S2N_TARGET} SANITIZERS "${${CMAKE_PROJECT_NAME}_SANITIZERS};fuzzer")
endif()

file(GLOB TESTLIB_SRC "tests/testlib/*.c")
file(GLOB TESTLIB_HEADERS "tests/testlib/*.h")

add_library(testss2n SHARED ${TESTLIB_HEADERS} ${TESTLIB_SRC})
target_include_directories(testss2n PRIVATE tests)
s2n_set_common_properties(testss2n NO_WEXTRA)
s2n_add_sanitizers(testss2n BLACKLIST "sanitizer-blacklist.txt")

if (ENABLE_FUZZ_TESTS)
    s2n_add_sanitizers(testss2n SANITIZERS "${${CMAKE_PROJECT_NAME}_SANITIZERS};fuzzer")
endif()

target_link_libraries(testss2n PUBLIC ${TEST_S2N_TARGET})

#run unit tests
file (GLOB TEST_LD_PRELOAD "tests/LD_PRELOAD/*.c")
add_library(allocator_overrides SHARED ${TEST_LD_PRELOAD})

include(CTest)
enable_testing()

if (NOT ENABLE_FUZZ_TESTS)
    if (RUN_UNIT_TESTS)
        file(GLOB UNITTESTS_SRC "tests/unit/*.c")
        foreach(test_case ${UNITTESTS_SRC})
            string(REGEX REPLACE ".+\\/(.+)\\.c" "\\1" test_case_name ${test_case})
            add_executable(${test_case_name} ${test_case})
            target_link_libraries(${test_case_name} PRIVATE testss2n PRIVATE m pthread)
            target_include_directories(${test_case_name} PRIVATE api)
            target_include_directories(${test_case_name} PRIVATE ./)
            target_include_directories(${test_case_name} PRIVATE tests)
            s2n_set_common_properties(${test_case_name} NO_WEXTRA NO_PEDANTIC)
            s2n_add_sanitizers(${test_case_name} SANITIZERS ${${CMAKE_PROJECT_NAME}_SANITIZERS})
            add_test(NAME ${test_case_name} COMMAND $<TARGET_FILE:${test_case_name}>
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit)

            set_property(
            TEST
                ${test_case_name}
            PROPERTY
                ENVIRONMENT LD_PRELOAD=$<TARGET_FILE:allocator_overrides>)
        endforeach(test_case)
    endif()

    add_executable(s2nc "bin/s2nc.c" "bin/echo.c")
    s2n_set_common_properties(s2nc NO_WEXTRA NO_PEDANTIC)
    target_link_libraries(s2nc s2n)
    target_include_directories(s2nc PRIVATE api)

    add_executable(s2nd "bin/s2nd.c" "bin/echo.c")
    s2n_set_common_properties(s2nd NO_WEXTRA NO_PEDANTIC)
    target_link_libraries(s2nd s2n)
    target_include_directories(s2nd PRIVATE api)

    if (RUN_INTEGRATION_TESTS)
        file(GLOB INTEGTESTS_SRC "tests/integration/*.py")
        foreach(integ_test_case ${INTEGTESTS_SRC})
            get_filename_component(integ_test_name ${integ_test_case} NAME_WE)

            add_test(NAME ${integ_test_name}
                    COMMAND python3 ${integ_test_case} --libcrypto ${S2N_LIBCRYPTO} ${S2ND_HOST} ${S2ND_PORT} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration)

            set_property(
                    TEST
                    ${integ_test_name}
                    PROPERTY
                    ENVIRONMENT DYLD_LIBRARY_PATH="${CMAKE_LIBRARY_OUTPUT_DIRECTORY}:${CMAKE_INSTALL_PREFIX}/lib:$DYLD_LIBRARY_PATH")
            set_property(
                    TEST
                    ${integ_test_name}
                    PROPERTY
                    ENVIRONMENT LD_LIBRARY_PATH="${CMAKE_LIBRARY_OUTPUT_DIRECTORY}:${CMAKE_INSTALL_PREFIX}/lib:$LD_LIBRARY_PATH")

        endforeach(integ_test_case)
    endif()

else()
    file(GLOB FUZZTESTS_SRC "tests/fuzz/*.c")
    s2n_add_fuzz_tests("${FUZZTESTS_SRC}" "")
endif()


#install the s2n files
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${API_HEADERS}")

install (
         TARGETS ${CMAKE_PROJECT_NAME}
         EXPORT "s2nTargets"
         ARCHIVE DESTINATION lib
         LIBRARY DESTINATION lib
         PUBLIC_HEADER DESTINATION "${INSTALL_INCLUDE_DIR}"
         COMPONENT dev
)

export(TARGETS ${CMAKE_PROJECT_NAME} FILE "s2nTargets.cmake")
export(PACKAGE ${CMAKE_PROJECT_NAME})

if(LibCrypto_ROOT_DIR)
     set(NON_SYS_LIB_CRYPTO_ROOT "${LibCrypto_ROOT_DIR}")
endif()

#for build output
set(CONF_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}")
configure_file(s2nConfig.cmake.in "${CMAKE_BINARY_DIR}/s2nConfig.cmake" @ONLY)

#for install output
set(CONF_INCLUDE_DIRS "\${S2N_CMAKE_DIR}/${REL_INCLUDE_DIR}")
configure_file(s2nConfig.cmake.in
"${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/s2nConfig.cmake" @ONLY)

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/FindLibCrypto.cmake" DESTINATION "${CMAKE_BINARY_DIR}")
file(RENAME "${CMAKE_BINARY_DIR}/FindLibCrypto.cmake" "${CMAKE_BINARY_DIR}/LibCryptoConfig.cmake")

install(FILES
    "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/s2nConfig.cmake"
    DESTINATION "${INSTALL_CMAKE_DIR}/s2n" COMPONENT dev)

install(FILES
    "${CMAKE_BINARY_DIR}/LibCryptoConfig.cmake"
    DESTINATION "${INSTALL_CMAKE_DIR}/LibCrypto" COMPONENT dev)

#install the cmake finder
install(EXPORT s2nTargets DESTINATION "${INSTALL_CMAKE_DIR}/s2n" COMPONENT dev)

