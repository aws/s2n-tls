cmake_minimum_required (VERSION 3.0)
project (s2n C)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries")
set(INSTALL_INCLUDE_DIR include CACHE PATH "Installation directory for header files")
set(INSTALL_CMAKE_DIR lib/cmake CACHE PATH "Installation directory for cmake files")

option(S2N_NO_PQ "Disables all Post Quantum Crypto code. You likely want this
for older compilers or uncommon platforms." OFF)
option(S2N_NO_PQ_ASM "Turns off the ASM for PQ Crypto even if it's available for the toolchain.
You likely want this on older compilers." OFF)

file(GLOB API_HEADERS "api/*.h")

file(GLOB CRYPTO_HEADERS "crypto/*.h")
file(GLOB CRYPTO_SRC "crypto/*.c")

file(GLOB ERROR_HEADERS "error/*.h")
file(GLOB ERROR_SRC "error/*.c")

file(GLOB STUFFER_HEADERS "stuffer/*.h")
file(GLOB STUFFER_SRC "stuffer/*.c")

file(GLOB_RECURSE TLS_HEADERS "tls/*.h")
file(GLOB_RECURSE TLS_SRC "tls/*.c")

file(GLOB UTILS_HEADERS "utils/*.h")
file(GLOB UTILS_SRC "utils/*.c")

# Always include the top-level pq-crypto/ files
file(GLOB PQ_HEADERS "pq-crypto/*.h")
file(GLOB PQ_SRC "pq-crypto/*.c")

if(S2N_NO_PQ)
    # PQ is disabled, so we do not include any PQ crypto code
    message(STATUS "S2N_NO_PQ flag was detected - disabling PQ crypto")
    set(S2N_NO_PQ_ASM ON)
else()
    # PQ is enabled, so include all of the PQ crypto code
    file(GLOB PQ_HEADERS
        "pq-crypto/*.h"
        "pq-crypto/bike_r1/*.h"
        "pq-crypto/bike_r2/*.h"
        "pq-crypto/sike_r1/*.h"
        "pq-crypto/sike_r2/*.h"
        "pq-crypto/kyber_r2/*.h"
        "pq-crypto/kyber_90s_r2/*.h")

    # The SIKE code #includes .c files directly, including all sike_r*/*.c breaks the build due to duplicates
    file(GLOB PQ_SRC
        "pq-crypto/*.c"
        "pq-crypto/bike_r1/*.c"
        "pq-crypto/bike_r2/*.c"
        "pq-crypto/sike_r1/fp_generic_r1.c"
        "pq-crypto/sike_r1/P503_r1.c"
        "pq-crypto/sike_r1/sike_r1_kem.c"
        "pq-crypto/sike_r1/fips202_r1.c"
        "pq-crypto/sike_r2/fips202.c"
        "pq-crypto/sike_r2/P434.c"
        "pq-crypto/kyber_r2/*.c"
        "pq-crypto/kyber_90s_r2/*.c")
endif()

##be nice to visual studio users
if(MSVC)
    source_group("Header Files\\s2n\\api" FILES ${API_HEADERS})
    source_group("Header Files\\s2n\\crypto" FILES ${CRYPTO_HEADERS})
    source_group("Header Files\\s2n\\error" FILES ${ERROR_HEADERS})
    source_group("Header Files\\s2n\\pq-crypto" FILES ${PQ_HEADERS})
    source_group("Header Files\\s2n\\stuffer" FILES ${STUFFER_HEADERS})
    source_group("Header Files\\s2n\\tls" FILES ${TLS_HEADERS})
    source_group("Header Files\\s2n\\utils" FILES ${UTILS_HEADERS})

    source_group("Source Files\\crypto" FILES ${CRYPTO_SRC})
    source_group("Source Files\\error" FILES ${ERROR_SRC})
    source_group("Source Files\\pq-crypto" FILES ${PQ_SRC})
    source_group("Source Files\\stuffer" FILES ${STUFFER_SRC})
    source_group("Source Files\\tls" FILES ${TLS_SRC})
    source_group("Source Files\\utils" FILES ${UTILS_SRC})
else()
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
endif()

# The PQ ASM try_compile has to come after we turn on pthread.
# If S2N_NO_PQ_ASM is defined, all PQ assembly options will
# remain turned off by default.
set(SIKEP434R2_ASM_SUPPORTED false)
set(ADX_SUPPORTED false)

if(S2N_NO_PQ_ASM)
    message(STATUS "S2N_NO_PQ_ASM flag was detected - disabling PQ crypto assembly code")
else()
    enable_language(ASM)

    # s2n_pq_asm_noop_test.c is just an empty main() function; the
    # try_compile function in older versions of CMake requires a main()
    try_compile(
        SIKEP434R2_ASM_SUPPORTED
        ${CMAKE_BINARY_DIR}
        SOURCES
            "${CMAKE_CURRENT_LIST_DIR}/tests/unit/s2n_pq_asm_noop_test.c"
            "${CMAKE_CURRENT_LIST_DIR}/pq-crypto/sike_r2/sikep434r2_fp_x64_asm.S"
    )

    if(SIKEP434R2_ASM_SUPPORTED)
        file(GLOB SIKEP434R2_ASM_SRC "pq-crypto/sike_r2/sikep434r2_fp_x64_asm.S")
        list(APPEND PQ_SRC ${SIKEP434R2_ASM_SRC})

        # The ADX instruction set is preferred for best performance, but not necessary.
        try_compile(
            ADX_SUPPORTED
            ${CMAKE_BINARY_DIR}
            SOURCES
                "${CMAKE_CURRENT_LIST_DIR}/tests/unit/s2n_pq_asm_noop_test.c"
                "${CMAKE_CURRENT_LIST_DIR}/pq-crypto/sike_r2/sikep434r2_fp_x64_asm.S"
            COMPILE_DEFINITIONS
                "-DS2N_ADX"
        )
    endif()
endif()

# Probe for execinfo.h extensions (not present on some systems, notably android)
include(CheckCSourceCompiles)

# Determine if execinfo.h is available
try_compile(
        S2N_HAVE_EXECINFO
        ${CMAKE_BINARY_DIR}
        SOURCES "${CMAKE_CURRENT_LIST_DIR}/tests/features/execinfo.c"
)

# Determine if cpuid.h is available
try_compile(
        S2N_CPUID_AVAILABLE
        ${CMAKE_BINARY_DIR}
        SOURCES "${CMAKE_CURRENT_LIST_DIR}/tests/features/cpuid.c"
)

# Determine if __attribute__((fallthrough)) is available
try_compile(
        FALL_THROUGH_SUPPORTED
        ${CMAKE_BINARY_DIR}
        SOURCES "${CMAKE_CURRENT_LIST_DIR}/tests/features/fallthrough.c"
        COMPILE_DEFINITIONS "-Werror"
)

# Determine if __restrict__ is available
try_compile(
        __RESTRICT__SUPPORTED
        ${CMAKE_BINARY_DIR}
        SOURCES "${CMAKE_CURRENT_LIST_DIR}/tests/features/__restrict__.c"
        COMPILE_DEFINITIONS "-Werror"
)

if(APPLE)
    set(OS_LIBS c Threads::Threads)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    set(OS_LIBS thr)
elseif(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
    set(OS_LIBS Threads::Threads)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
    set(OS_LIBS Threads::Threads dl)
else()
    set(OS_LIBS Threads::Threads dl rt)
endif()

file(GLOB S2N_HEADERS
    ${API_HEADERS}
    ${CRYPTO_HEADERS}
    ${ERROR_HEADERS}
    ${PQ_HEADERS}
    ${STUFFER_HEADERS}
    ${TLS_HEADERS}
    ${UTILS_HEADERS}
)

file(GLOB S2N_SRC
    ${CRYPTO_SRC}
    ${ERROR_SRC}
    ${PQ_SRC}
    ${STUFFER_SRC}
    ${TLS_SRC}
    ${UTILS_SRC}
)

add_library(${PROJECT_NAME} ${S2N_HEADERS} ${S2N_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE C)

set(CMAKE_C_FLAGS_DEBUGOPT "")

target_compile_options(${PROJECT_NAME} PRIVATE -pedantic -std=gnu99 -Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts
        -Wuninitialized -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security
        -Wno-missing-braces -fvisibility=hidden -DS2N_EXPORTS
        -Wa,--noexecstack
)

set(CMAKE_SHARED_LINKER_FLAGS -Wl,-z,noexecstack,-z,relro,-z,now)

if(S2N_NO_PQ)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_NO_PQ)
endif()

if(SIKEP434R2_ASM_SUPPORTED)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_SIKEP434R2_ASM)
    message(STATUS "Enabling SIKEP434R2 assembly code")
endif()

if(ADX_SUPPORTED)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_ADX)
    message(STATUS "Support for ADX assembly instructions detected")
endif()

if(S2N_HAVE_EXECINFO)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_HAVE_EXECINFO)
endif()

if(S2N_CPUID_AVAILABLE)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_CPUID_AVAILABLE)
endif()

target_compile_options(${PROJECT_NAME} PUBLIC -fPIC)

target_compile_definitions(${PROJECT_NAME} PRIVATE -D_POSIX_C_SOURCE=200809L)
if(CMAKE_BUILD_TYPE MATCHES Release)
    target_compile_definitions(${PROJECT_NAME} PRIVATE -D_FORTIFY_SOURCE=2)
endif()

if(NO_STACK_PROTECTOR)
    target_compile_options(${PROJECT_NAME} PRIVATE -Wstack-protector -fstack-protector-all)
endif()

if(S2N_UNSAFE_FUZZING_MODE)
    target_compile_options(${PROJECT_NAME} PRIVATE -fsanitize-coverage=trace-pc-guard -fsanitize=address,undefined,leak -fuse-ld=gold -DS2N_ADDRESS_SANITIZER=1)
endif()

if (FALL_THROUGH_SUPPORTED)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_FALL_THROUGH_SUPPORTED)
endif()

if (__RESTRICT__SUPPORTED)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N___RESTRICT__SUPPORTED)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

find_package(LibCrypto REQUIRED)
target_link_libraries(${PROJECT_NAME} PUBLIC LibCrypto::Crypto ${OS_LIBS} m)

target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/api> $<INSTALL_INTERFACE:include>)

target_include_directories(${PROJECT_NAME} PRIVATE $<TARGET_PROPERTY:LibCrypto::Crypto,INTERFACE_INCLUDE_DIRECTORIES>)

include(CTest)
if (BUILD_TESTING)
    enable_testing()

    file(GLOB TESTLIB_SRC "tests/testlib/*.c")
    file(GLOB TESTLIB_HEADERS "tests/testlib/*.h" "tests/s2n_test.h")

    add_library(testss2n STATIC ${TESTLIB_HEADERS} ${TESTLIB_SRC})
    target_include_directories(testss2n PUBLIC tests)
    target_compile_options(testss2n PRIVATE -std=gnu99)
    target_link_libraries(testss2n PUBLIC ${PROJECT_NAME})
    target_include_directories(testss2n PUBLIC $<TARGET_PROPERTY:LibCrypto::Crypto,INTERFACE_INCLUDE_DIRECTORIES>)

    #run unit tests
    file (GLOB TEST_LD_PRELOAD "tests/LD_PRELOAD/*.c")
    add_library(allocator_overrides SHARED ${TEST_LD_PRELOAD})

    file(GLOB UNITTESTS_SRC "tests/unit/*.c")
    foreach(test_case ${UNITTESTS_SRC})
        string(REGEX REPLACE ".+\\/(.+)\\.c" "\\1" test_case_name ${test_case})

        add_executable(${test_case_name} ${test_case})
        target_include_directories(${test_case_name} PRIVATE api)
        target_include_directories(${test_case_name} PRIVATE ./)
        target_include_directories(${test_case_name} PRIVATE tests)
        target_link_libraries(${test_case_name} PRIVATE testss2n)
        target_compile_options(${test_case_name} PRIVATE -Wno-implicit-function-declaration -Wno-deprecated -D_POSIX_C_SOURCE=200809L -std=gnu99)
        add_test(NAME ${test_case_name} COMMAND $<TARGET_FILE:${test_case_name}> WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit)

        set_property(
        TEST
            ${test_case_name}
        PROPERTY
            ENVIRONMENT LD_PRELOAD=$<TARGET_FILE:allocator_overrides>)

        set_property(
        TEST
            ${test_case_name}
        PROPERTY
            ENVIRONMENT S2N_DONT_MLOCK=1)

    endforeach(test_case)

    add_executable(s2nc "bin/s2nc.c" "bin/echo.c" "bin/https.c" "bin/common.c")
    target_link_libraries(s2nc ${PROJECT_NAME})
    target_include_directories(s2nc PRIVATE $<TARGET_PROPERTY:LibCrypto::Crypto,INTERFACE_INCLUDE_DIRECTORIES>)
    target_include_directories(s2nc PRIVATE api)
    target_compile_options(s2nc PRIVATE -std=gnu99 -D_POSIX_C_SOURCE=200112L)

    add_executable(s2nd "bin/s2nd.c" "bin/echo.c" "bin/https.c" "bin/common.c")
    target_link_libraries(s2nd ${PROJECT_NAME})
    target_include_directories(s2nd PRIVATE $<TARGET_PROPERTY:LibCrypto::Crypto,INTERFACE_INCLUDE_DIRECTORIES>)
    target_include_directories(s2nd PRIVATE api)
    target_compile_options(s2nd PRIVATE -std=gnu99 -D_POSIX_C_SOURCE=200112L)

    if(BENCHMARK)
        find_package(benchmark REQUIRED)
        file(GLOB BENCHMARK_SRC "tests/benchmark/*.cc")
        enable_language(CXX)
        foreach(benchmark ${BENCHMARK_SRC})
            string(REGEX REPLACE ".+\\/(.+)\\.cc" "\\1" benchmark_name ${benchmark})
            add_executable(${benchmark_name} ${benchmark})
            target_include_directories(${benchmark_name} PRIVATE api)
            target_include_directories(${benchmark_name} PRIVATE tests)
            target_link_libraries(${benchmark_name} PUBLIC ${PROJECT_NAME} testss2n benchmark::benchmark)

            # Based off the flags in tests/benchmark/Makefile
            target_compile_options(${benchmark_name} PRIVATE -pedantic -Wall -Werror -Wunused -Wcomment -Wchar-subscripts
                    -Wuninitialized -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings -Wno-deprecated-declarations
                    -Wno-unknown-pragmas -Wformat-security -Wno-missing-braces -fvisibility=hidden -Wno-unreachable-code
                    -Wno-unused-but-set-variable)
        endforeach(benchmark)

    endif()
endif()



#install the s2n files
install(FILES ${API_HEADERS} DESTINATION "include/" COMPONENT Development)

if (UNIX AND NOT APPLE)
    include(GNUInstallDirs)
elseif(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

install(
        TARGETS ${PROJECT_NAME}
        EXPORT ${PROJECT_NAME}-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Development
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Runtime
        RUNTIME DESTINATION bin COMPONENT Runtime
)

configure_file("cmake/${PROJECT_NAME}-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        @ONLY)

if (BUILD_SHARED_LIBS)
   set (TARGET_DIR "shared")
else()
   set (TARGET_DIR "static")
endif()

install(EXPORT "${PROJECT_NAME}-targets"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/cmake/${TARGET_DIR}"
        NAMESPACE AWS::
        COMPONENT Development)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/cmake/"
        COMPONENT Development)

install(FILES "cmake/modules/FindLibCrypto.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/cmake/modules/"
        COMPONENT Development)

