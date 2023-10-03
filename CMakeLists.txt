cmake_minimum_required (VERSION 3.0)
project (s2n C)

if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW) #option does nothing when a normal variable of the same name exists.
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries")
set(INSTALL_INCLUDE_DIR include CACHE PATH "Installation directory for header files")
set(INSTALL_CMAKE_DIR lib/cmake CACHE PATH "Installation directory for cmake files")

set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)

# These Version numbers are for major updates only- we won't track minor/patch updates here.
set(VERSION_MAJOR 1)
set(VERSION_MINOR 0)
set(VERSION_PATCH 0)

option(S2N_NO_PQ "Disables all Post Quantum Crypto code. You likely want this
for older compilers or uncommon platforms." OFF)
option(S2N_NO_PQ_ASM "Turns off the ASM for PQ Crypto even if it's available for the toolchain.
You likely want this on older compilers." OFF)
option(SEARCH_LIBCRYPTO "Set this if you want to let S2N search libcrypto for you,
otherwise a crypto target needs to be defined." ON)
option(UNSAFE_TREAT_WARNINGS_AS_ERRORS "Compiler warnings are treated as errors. Warnings may
indicate danger points where you should verify with the S2N-TLS developers that the security of
the library is not compromised. Turn this OFF to ignore warnings." ON)
option(S2N_INTERN_LIBCRYPTO "This ensures that s2n-tls is compiled and deployed with a specific
version of libcrypto by interning the code and hiding symbols. This also enables s2n-tls to be
loaded in an application with an otherwise conflicting libcrypto version." OFF)
option(S2N_LTO, "Enables link time optimizations when building s2n-tls." OFF)
option(S2N_STACKTRACE "Enables stacktrace functionality in s2n-tls. Note that this functionality is
only available on platforms that support execinfo." ON)
option(COVERAGE "Enable profiling collection for code coverage calculation" OFF)
option(S2N_INTEG_TESTS "Enable the integrationv2 tests" OFF)
option(S2N_FAST_INTEG_TESTS "Enable the integrationv2 with more parallelism, only has effect if S2N_INTEG_TESTS=ON" OFF)
option(S2N_INSTALL_S2NC_S2ND "Install the binaries s2nc and s2nd" OFF)
option(TSAN "Enable ThreadSanitizer to test thread safety" OFF)
option(ASAN "Enable AddressSanitizer to test memory safety" OFF)

# Turn BUILD_TESTING=ON by default
include(CTest)

file(GLOB API_HEADERS "api/*.h")
file(GLOB API_UNSTABLE_HEADERS "api/unstable/*.h")

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

message(STATUS "Detected CMAKE_SYSTEM_PROCESSOR as ${CMAKE_SYSTEM_PROCESSOR}")

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(STATUS "Detected 32-Bit system - disabling PQ crypto assembly optimizations")
  set(S2N_NO_PQ_ASM ON)
else()
    message(STATUS "Detected 64-Bit system")
endif()

if(S2N_NO_PQ)
    # PQ is disabled, so we do not include any PQ crypto code
    message(STATUS "S2N_NO_PQ flag was detected - disabling PQ crypto")
    set(S2N_NO_PQ_ASM ON)
else()
    # PQ is enabled, so include all of the PQ crypto code
    file(GLOB PQ_HEADERS
        "pq-crypto/*.h"
        "pq-crypto/kyber_r3/*.h")

    file(GLOB PQ_SRC
        "pq-crypto/*.c"
        "pq-crypto/kyber_r3/*.c")
endif()

##be nice to visual studio users
if(MSVC)
    source_group("Header Files\\s2n\\api" FILES ${API_HEADERS} ${API_UNSTABLE_HEADERS})
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

if(APPLE)
    set(OS_LIBS c Threads::Threads)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    set(OS_LIBS thr execinfo)
elseif(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
    set(OS_LIBS Threads::Threads)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    set(OS_LIBS Threads::Threads kvm)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
    set(OS_LIBS Threads::Threads dl)
else()
    set(OS_LIBS Threads::Threads dl rt)
endif()

# Compiling the unit tests rely on S2N_TEST_IN_FIPS_MODE to be set correctly
if(S2N_FIPS)
    add_definitions(-DS2N_TEST_IN_FIPS_MODE)
endif()

file(GLOB S2N_HEADERS
    ${API_HEADERS}
    ${API_UNSTABLE_HEADERS}
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

# Version numbers are for major updates only- we won't track minor/patch updates here.
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION ${VERSION_MAJOR})

set(CMAKE_C_FLAGS_DEBUGOPT "")

target_compile_options(${PROJECT_NAME} PRIVATE -pedantic -std=gnu99 -Wall -Wimplicit -Wunused -Wcomment -Wchar-subscripts
        -Wuninitialized -Wshadow -Wcast-align -Wwrite-strings -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security
        -Wno-missing-braces -Wsign-compare -Wno-strict-prototypes -Wa,--noexecstack
)

if (UNSAFE_TREAT_WARNINGS_AS_ERRORS)
    target_compile_options(${PROJECT_NAME} PRIVATE -Werror )
endif ()

if(BUILD_TESTING AND BUILD_SHARED_LIBS)
    target_compile_options(${PROJECT_NAME} PRIVATE -fvisibility=default)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -fvisibility=hidden -DS2N_EXPORTS)
endif()

if(S2N_LTO)
    target_compile_options(${PROJECT_NAME} PRIVATE -flto)
    # if we're building a static lib, make it easier for consuming applications to also perform LTO
    if(NOT BUILD_SHARED_LIBS)
        target_compile_options(${PROJECT_NAME} PRIVATE -ffunction-sections -fdata-sections)
    endif()
endif()

if(NOT APPLE)
    set(CMAKE_SHARED_LINKER_FLAGS -Wl,-z,noexecstack,-z,relro,-z,now)
endif()

if(S2N_NO_PQ)
    add_definitions(-DS2N_NO_PQ)
endif()

# Whether to fail the build when compiling s2n's portable C code with non-portable assembly optimizations. Doing this
# can lead to runtime crashes if build artifacts are built on modern hardware, but deployed to older hardware without
# newer CPU instructions. s2n, by default, should be backwards compatible with older CPU types so this flag should be
# enabled in s2n's CI builds and tests, but other consumers of s2n may have stronger control of what CPU types they
# deploy to, and can enable more CPU optimizations.
if(S2N_BLOCK_NONPORTABLE_OPTIMIZATIONS)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_BLOCK_NONPORTABLE_OPTIMIZATIONS=1)
endif()

target_compile_options(${PROJECT_NAME} PUBLIC -fPIC)

add_definitions(-D_POSIX_C_SOURCE=200809L)
if(CMAKE_BUILD_TYPE MATCHES Release)
    add_definitions(-D_FORTIFY_SOURCE=2)
endif()

if(NO_STACK_PROTECTOR)
    target_compile_options(${PROJECT_NAME} PRIVATE -Wstack-protector -fstack-protector-all)
endif()

if(S2N_UNSAFE_FUZZING_MODE)
    target_compile_options(${PROJECT_NAME} PRIVATE -fsanitize-coverage=trace-pc-guard -fsanitize=address,undefined,leak -fuse-ld=gold -DS2N_ADDRESS_SANITIZER=1)
endif()

if(TSAN)
    target_compile_options(${PROJECT_NAME} PUBLIC -fsanitize=thread -DS2N_THREAD_SANITIZER=1)
    target_link_options(${PROJECT_NAME} PUBLIC -fsanitize=thread)
endif()

if(ASAN)
    target_compile_options(${PROJECT_NAME} PUBLIC -fsanitize=address -DS2N_ADDRESS_SANITIZER=1)
    target_link_options(${PROJECT_NAME} PUBLIC -fsanitize=address)
endif()

if(TSAN OR ASAN)
    # no-omit-frame-pointer and no-optimize-sibling-calls provide better stack traces
    target_compile_options(${PROJECT_NAME} PUBLIC -fno-omit-frame-pointer -fno-optimize-sibling-calls)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

if (NOT $ENV{S2N_LIBCRYPTO} MATCHES "awslc")
    # add cast-qual back in for non AWS-LC
    target_compile_options(${PROJECT_NAME} PRIVATE -Wcast-qual)
endif()

if (COVERAGE)
    # https://cmake.org/cmake/help/latest/variable/CMAKE_LANG_COMPILER_ID.html
    # Coverage is done using LLVM source based coverage. This is only supported
    # on LLVM compilers. GCC would fail with "unrecognized compile options"
    # on -fprofile-instr-generate -fcoverage-mapping flags.
    if (NOT ${CMAKE_C_COMPILER_ID} MATCHES Clang)
        message(FATAL_ERROR "This project requires clang for coverage support")
    endif()
    target_compile_options(${PROJECT_NAME} PUBLIC -fprofile-instr-generate -fcoverage-mapping)
    target_link_options(${PROJECT_NAME} PUBLIC -fprofile-instr-generate -fcoverage-mapping)
endif()

# For interning, we need to find the static libcrypto library. Cmake configs
# can branch on the variable BUILD_SHARED_LIBS to e.g. avoid having to define
# multiple targets. An example is AWS-LC:
# https://github.com/awslabs/aws-lc/blob/main/crypto/cmake/crypto-config.cmake#L5
if (S2N_INTERN_LIBCRYPTO)
    set(BUILD_SHARED_LIBS_BACKUP ${BUILD_SHARED_LIBS})
    set(BUILD_SHARED_LIBS OFF)
endif()

# Work around target differences
if (TARGET crypto)
    message(STATUS "S2N found target: crypto")
    set(LINK_LIB "crypto")
else()
    find_package(crypto REQUIRED)
    message(STATUS "Using libcrypto from the cmake path")
    set(LINK_LIB "AWS::crypto")
endif()

if (S2N_INTERN_LIBCRYPTO)
    # Restore the old BUILD_SHARED_LIBS value
    set(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_BACKUP})
    message(STATUS "Enabling libcrypto interning")
endif()

if (NOT DEFINED CMAKE_AR)
    message(STATUS "CMAKE_AR undefined, setting to `ar` by default")
    SET(CMAKE_AR ar)
else()
    message(STATUS "CMAKE_AR found: ${CMAKE_AR}")
endif()

if (NOT DEFINED CMAKE_RANLIB)
    message(STATUS "CMAKE_RANLIB undefined, setting to `ranlib` by default")
    SET(CMAKE_RANLIB ranlib)
else()
    message(STATUS "CMAKE_RANLIB found: ${CMAKE_RANLIB}")
endif()

if (NOT DEFINED CMAKE_OBJCOPY)
    message(STATUS "CMAKE_OBJCOPY undefined, setting to `objcopy` by default")
    SET(CMAKE_OBJCOPY objcopy)
else()
    message(STATUS "CMAKE_OBJCOPY found: ${CMAKE_OBJCOPY}")
endif()

# Sets the result of the feature probe to `IS_AVAILABLE`
function(feature_probe_result PROBE_NAME IS_AVAILABLE)
    # normalize the boolean value
    if(IS_AVAILABLE)
        set(NORMALIZED TRUE)
    else()
        set(NORMALIZED FALSE)
    endif()

    # indicate the status of the probe
    message(STATUS "feature ${PROBE_NAME}: ${NORMALIZED}")
    # set the probe result in the parent scope for other probes
    set(${PROBE_NAME} ${NORMALIZED} PARENT_SCOPE)

    # define the probe if available
    if(NORMALIZED)
        add_definitions(-D${PROBE_NAME})
    endif()
endfunction()

# Tries to compile a feature probe and initializes the corresponding flags
function(feature_probe PROBE_NAME)
    # Load the global probe flags
    file(READ "${CMAKE_CURRENT_LIST_DIR}/tests/features/GLOBAL.flags" GLOBAL_FILE)
    string(REPLACE "\n" "" GLOBAL_FLAGS "${GLOBAL_FILE}")

    # Load the probe's flags
    file(READ "${CMAKE_CURRENT_LIST_DIR}/tests/features/${PROBE_NAME}.flags" PROBE_FILE)
    string(REPLACE "\n" "" PROBE_FLAGS "${PROBE_FILE}")

    # Try to compile the probe with the given flags
    try_compile(
        IS_AVAILABLE
        ${CMAKE_BINARY_DIR}
        SOURCES "${CMAKE_CURRENT_LIST_DIR}/tests/features/${PROBE_NAME}.c"
        LINK_LIBRARIES ${LINK_LIB} ${OS_LIBS}
        CMAKE_FLAGS ${ADDITIONAL_FLAGS}
        COMPILE_DEFINITIONS -c ${GLOBAL_FLAGS} ${PROBE_FLAGS}
        ${ARGN}
        OUTPUT_VARIABLE TRY_COMPILE_OUTPUT
    )
    # Uncomment the line below to get the output of the try_compile command
    #message(STATUS "Output of try_compile: ${TRY_COMPILE_OUTPUT}")

    # Set the result of the probe
    feature_probe_result(${PROBE_NAME} ${IS_AVAILABLE})

    # Make sure the variable is set in the parent scope
    set(${PROBE_NAME} ${IS_AVAILABLE} PARENT_SCOPE)

    # Set the flags that we used for the probe
    set(${PROBE_NAME}_FLAGS ${PROBE_FLAGS} PARENT_SCOPE)
endfunction()

# Iterate over all of the features and try to compile them
FILE(GLOB FEATURE_SRCS "${CMAKE_CURRENT_LIST_DIR}/tests/features/*.c")
list(SORT FEATURE_SRCS)
foreach(file ${FEATURE_SRCS})
    get_filename_component(feature_name ${file} NAME_WE)
    feature_probe(${feature_name})
endforeach()

# FreeBSD might need to link to execinfo explicitly
if(NOT S2N_EXECINFO_AVAILABLE AND CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    feature_probe(S2N_EXECINFO_AVAILABLE LINK_LIBRARIES execinfo)
endif()

# Stack traces are only available if execinfo is
if (NOT S2N_EXECINFO_AVAILABLE)
    set(S2N_STACKTRACE FALSE)
endif()
feature_probe_result(S2N_STACKTRACE ${S2N_STACKTRACE})

set(S2N_KYBER512R3_AVX2_BMI2 FALSE)
if(NOT S2N_NO_PQ_ASM)
    # Kyber Round-3 code has several different optimizations which require
    # specific compiler flags to be supported by the compiler.
    # So for each needed instruction set extension we check if the compiler
    # supports it and set proper compiler flags to be added later to the
    # Kyber compilation units.
    if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "^(x86_64|amd64|AMD64)$")
        # Some platforms support -mavx2 flag but not m256 intrinsics required to use them. Only enable Kyber assembly
        # optimizations if both are supported. See https://github.com/aws/s2n-tls/pull/3005 for more info.
        if(S2N_KYBER512R3_AVX2_BMI2_SUPPORTED AND S2N_KYBER512R3_M256_INTRINSICS_SUPPORTED)
            set(S2N_KYBER512R3_AVX2_BMI2 TRUE)
            enable_language(ASM)

            # add the assembly files to the project
            FILE(GLOB KYBER512R3_AVX2_BMI2_ASM_SRCS "pq-crypto/kyber_r3/*_avx2.S")
            target_sources(${PROJECT_NAME} PRIVATE ${KYBER512R3_AVX2_BMI2_ASM_SRCS})

            # compile the C files with avx flags
            FILE(GLOB KYBER512R3_AVX2_BMI2_SRCS "pq-crypto/kyber_r3/*_avx2.c")
            set_source_files_properties(${KYBER512R3_AVX2_BMI2_SRCS} PROPERTIES COMPILE_FLAGS ${S2N_KYBER512R3_AVX2_BMI2_SUPPORTED_FLAGS})
        endif()
    endif()
endif()
feature_probe_result(S2N_KYBER512R3_AVX2_BMI2 ${S2N_KYBER512R3_AVX2_BMI2})

if (S2N_INTERN_LIBCRYPTO)

    # Check if the AWS::crypto target has beeen added and handle it
    if (TARGET AWS::crypto)
        # Get the target library type (shared or static)
        get_target_property(target_type AWS::crypto TYPE)
        message(STATUS "AWS::crypto target type: ${target_type}")

        # If we didn't find the a target with static library type, fallback to
        # existing crypto_STATIC_LIBRARY and crypto_INCLUDE_DIR
        if (target_type STREQUAL STATIC_LIBRARY)
            # We need an path to the include directory and libcrypto.a archive.
            # The finder module defines these appropriately, but if we go through
            # the target config we need to query this information from the target
            # first.
            get_target_property(crypto_STATIC_LIBRARY AWS::crypto LOCATION)
            get_target_property(crypto_INCLUDE_DIR AWS::crypto INTERFACE_INCLUDE_DIRECTORIES)
        endif()
    endif()

    if (NOT crypto_STATIC_LIBRARY)
        message(FATAL_ERROR "libcrypto interning requires a static build of libcrypto.a to be available")
    endif()

    message(STATUS "crypto_STATIC_LIBRARY: ${crypto_STATIC_LIBRARY}")
    message(STATUS "crypto_INCLUDE_DIR: ${crypto_INCLUDE_DIR}")

    # Don't call link_target_libraries here, just make sure the libcrypto include dir is in the path
    include_directories("${crypto_INCLUDE_DIR}")

    add_custom_command(
        OUTPUT libcrypto.symbols
        COMMAND
          # copy the static version of libcrypto
          cp ${crypto_STATIC_LIBRARY} s2n_libcrypto.a &&
          # dump all of the symbols and prefix them with `s2n$`
          bash -c "${CMAKE_NM} s2n_libcrypto.a | awk '/ [A-Z] /{print $3\" s2n$\"$3}' | sort | uniq > libcrypto.symbols" &&
          # redefine the libcrypto libary symbols
          ${CMAKE_OBJCOPY} --redefine-syms libcrypto.symbols s2n_libcrypto.a &&
          rm -rf s2n_libcrypto &&
          mkdir s2n_libcrypto &&
          cd s2n_libcrypto &&
          # extract libcrypto objects from the archive
          ${CMAKE_AR} x ../s2n_libcrypto.a &&
          # rename all of the object files so we don't have any object name collisions
          bash -c "find . -name '*.o' -type f -print0 | xargs -0 -n1 -- basename | xargs -I{} mv {} s2n_crypto__{}"
        VERBATIM
    )

    add_custom_target(s2n_libcrypto ALL
      DEPENDS libcrypto.symbols
    )
    add_dependencies(${PROJECT_NAME} s2n_libcrypto)
    add_definitions(-DS2N_INTERN_LIBCRYPTO)

    if ((BUILD_SHARED_LIBS AND BUILD_TESTING) OR NOT BUILD_SHARED_LIBS)
        # if libcrypto needs to be interned, rewrite libcrypto references so use of internal functions will link correctly
        add_custom_command(
            TARGET ${PROJECT_NAME} PRE_LINK
            COMMAND
              find "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/${PROJECT_NAME}.dir" -name '*.c.o' -exec objcopy --redefine-syms libcrypto.symbols {} \\\;
        )
    endif()

    # copy the static libcrypto into the final artifact
    if (BUILD_SHARED_LIBS)
        if (BUILD_TESTING)
            # if we're building tests, we export the prefixed symbols so tests can link to them
            set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS
                "-Wl,--whole-archive s2n_libcrypto.a -Wl,--no-whole-archive")
        else()
            # if we're not building tests, then just copy the original archive, unmodified
            set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS
                "-Wl,--whole-archive ${crypto_STATIC_LIBRARY} -Wl,--no-whole-archive -Wl,--exclude-libs=ALL")
        endif()
    else()
        # add all of the prefixed symbols to the archive
        add_custom_command(
            TARGET ${PROJECT_NAME} POST_BUILD
            DEPENDS libcrypto.symbols
            COMMAND
                bash -c "${CMAKE_AR} -r lib/libs2n.a s2n_libcrypto/*.o"
            VERBATIM
        )
    endif()
else()
    # LINK_LIB is set above after checking targets. It handles the find_package craziness.
    target_link_libraries(${PROJECT_NAME} PUBLIC ${LINK_LIB})
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC ${OS_LIBS} m)

target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/api> $<INSTALL_INTERFACE:include>)

if (BUILD_TESTING)
    enable_testing()

    file(GLOB TESTLIB_SRC "tests/testlib/*.c")
    file(GLOB EXAMPLES_SRC "docs/examples/*.c")
    file(GLOB TESTLIB_HEADERS "tests/testlib/*.h" "tests/s2n_test.h")

    add_library(testss2n STATIC ${TESTLIB_HEADERS} ${TESTLIB_SRC} ${EXAMPLES_SRC})
    target_include_directories(testss2n PUBLIC tests)
    target_compile_options(testss2n PRIVATE -std=gnu99)
    target_link_libraries(testss2n PUBLIC ${PROJECT_NAME})

    if (S2N_INTERN_LIBCRYPTO)
        # if libcrypto was interned, rewrite libcrypto symbols so use of internal functions will link correctly
        add_custom_command(
            TARGET testss2n POST_BUILD
            COMMAND
                objcopy --redefine-syms libcrypto.symbols lib/libtestss2n.a
        )
    endif()

    #run unit tests
    file (GLOB TEST_LD_PRELOAD "tests/LD_PRELOAD/*.c")
    add_library(allocator_overrides SHARED ${TEST_LD_PRELOAD})

    set(UNIT_TEST_ENVS S2N_DONT_MLOCK=1)
    if (TSAN OR ASAN)
        set(UNIT_TEST_ENVS ${UNIT_TEST_ENVS} S2N_ADDRESS_SANITIZER=1)
    endif()
    if(TSAN)
        set(TSAN_SUPPRESSIONS_FILE ${CMAKE_SOURCE_DIR}/tests/.tsan_suppressions)
        if(NOT EXISTS ${TSAN_SUPPRESSIONS_FILE})
            message(FATAL_ERROR "TSAN suppression file ${TSAN_SUPPRESSIONS_FILE} missing")
        endif()
        set(TSAN_OPTIONS suppressions=${TSAN_SUPPRESSIONS_FILE})
        if(DEFINED ENV{TSAN_OPTIONS})
            set(TSAN_OPTIONS "${TSAN_OPTIONS} $ENV{TSAN_OPTIONS}")
        endif()
        set(UNIT_TEST_ENVS ${UNIT_TEST_ENVS} TSAN_OPTIONS=${TSAN_OPTIONS})
    endif()
    if(ASAN)
        # "detect_odr_violation" detects violations of the "one definition rule",
        # ensuring that symbols are only defined once.
        # But some of our unit tests intentionally include *.c files for testing,
        # resulting in duplicate global values.
        set(ASAN_OPTIONS detect_odr_violation=0)
        if(DEFINED ENV{ASAN_OPTIONS})
            set(ASAN_OPTIONS "${ASAN_OPTIONS} $ENV{ASAN_OPTIONS}")
        endif()
        set(UNIT_TEST_ENVS ${UNIT_TEST_ENVS} ASAN_OPTIONS=${ASAN_OPTIONS})
    endif()
    message(STATUS "Running tests with environment: ${UNIT_TEST_ENVS}")

    file(GLOB UNITTESTS_SRC "tests/unit/*.c")
    foreach(test_case ${UNITTESTS_SRC})
        string(REGEX REPLACE ".+\\/(.+)\\.c" "\\1" test_case_name ${test_case})

        add_executable(${test_case_name} ${test_case})
        target_include_directories(${test_case_name} PRIVATE api)
        target_include_directories(${test_case_name} PRIVATE ./)
        target_include_directories(${test_case_name} PRIVATE tests)
        target_link_libraries(${test_case_name} PRIVATE testss2n)
        if (S2N_INTERN_LIBCRYPTO)
            # if libcrypto was interned, rewrite libcrypto symbols so use of internal functions will link correctly
            add_custom_command(
                TARGET ${test_case_name} PRE_LINK
                COMMAND
                  find . -name '${test_case_name}.c.o' -exec objcopy --redefine-syms libcrypto.symbols {} \\\;
            )
        endif()
        target_compile_options(${test_case_name} PRIVATE -Wno-implicit-function-declaration -Wno-deprecated -D_POSIX_C_SOURCE=200809L -std=gnu99)
        if (S2N_LTO)
            target_compile_options(${test_case_name} PRIVATE -flto)
        endif()
        add_test(NAME ${test_case_name} COMMAND $<TARGET_FILE:${test_case_name}> WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit)
        set_property(TEST ${test_case_name} PROPERTY LABELS "unit")
        set_property(TEST ${test_case_name} PROPERTY ENVIRONMENT ${UNIT_TEST_ENVS})

    endforeach(test_case)

    add_executable(s2nc "bin/s2nc.c" "bin/echo.c" "bin/https.c" "bin/common.c")
    target_link_libraries(s2nc ${PROJECT_NAME})

    target_include_directories(s2nc PRIVATE api)
    target_compile_options(s2nc PRIVATE -std=gnu99)


    add_executable(s2nd "bin/s2nd.c" "bin/echo.c" "bin/https.c" "bin/common.c")
    target_link_libraries(s2nd ${PROJECT_NAME})

    target_include_directories(s2nd PRIVATE api)
    target_compile_options(s2nd PRIVATE -std=gnu99)

    if(S2N_LTO)
        target_compile_options(s2nc PRIVATE -flto)
        target_compile_options(s2nd PRIVATE -flto)
    endif()

    if(BENCHMARK)
        find_package(benchmark REQUIRED)
        file(GLOB BENCHMARK_SRC "tests/benchmark/*.cc")
        file(GLOB BENCHMARK_UTILS "tests/benchmark/utils/*.cc")
        enable_language(CXX)
        foreach(benchmark ${BENCHMARK_SRC})
            string(REGEX REPLACE ".+\\/(.+)\\.cc" "\\1" benchmark_name ${benchmark})
            add_executable(${benchmark_name} ${benchmark} "bin/echo.c" "bin/common.c" ${BENCHMARK_UTILS})
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

    if (S2N_INTEG_TESTS)
        find_package (Python3 COMPONENTS Interpreter Development)
        file(GLOB integv2_test_files "${PROJECT_SOURCE_DIR}/tests/integrationv2/test_*.py")
        foreach(test_file_path ${integv2_test_files})
            get_filename_component(test_filename ${test_file_path} NAME_WE)
            string(REGEX REPLACE "^test_" "integrationv2_" test_target ${test_filename})
            if (S2N_INTEG_NIX)
                # For Nix and environments where LD_LIBRARY_PATH is already correct.
                # We're also dropping tox and calling pytest directly, because
                # Nix is already handling all of the python setup.
                if (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" AND ${test_target} STREQUAL "integrationv2_sslyze" )
                  # sslyze/nassl is not available on aarch64.
                  message(WARNING "Skipping ${test_target} due to missing tools on ${CMAKE_SYSTEM_PROCESSOR}")
                  continue()
                endif()
                message(STATUS "Adding integ test ${test_target}")
                add_test(NAME ${test_target}
                        COMMAND
                        pytest
                        -x -n=1 --maxfail=1 --reruns=0 --cache-clear -rpfsq
                        -o log_cli=true --log-cli-level=DEBUG --provider-version=$ENV{S2N_LIBCRYPTO}
                        --provider-criterion=off --fips-mode=0 --no-pq=0 ${test_file_path}
                        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/integrationv2
                )
            else()
                # For use with libcryptos built into test-deps, and not in LD_LIBRARY_PATH.
                # This is a duplication of tests/integrationv2/Makefile and
                # can go away once all the Nix porting is finished.
                add_test(NAME ${test_target}
                        COMMAND
                        ${CMAKE_COMMAND} -E env
                        DYLD_LIBRARY_PATH=${PROJECT_SOURCE_DIR}/libcrypto-root/lib:$ENV{DYLD_LIBRARY_PATH}
                        LD_LIBRARY_PATH=${PROJECT_SOURCE_DIR}/libcrypto-root/lib:${PROJECT_SOURCE_DIR}/test-deps/openssl-1.1.1/lib:${PROJECT_SOURCE_DIR}/test-deps/gnutls37/nettle/lib:$ENV{LD_LIBRARY_PATH}
                        PATH=${PROJECT_SOURCE_DIR}/bin:${PROJECT_SOURCE_DIR}/test-deps/openssl-1.1.1/bin:${PROJECT_SOURCE_DIR}/test-deps/gnutls37/bin:$ENV{PATH}
                        PYTHONNOUSERSITE=1
                        S2N_INTEG_TEST=1
                        TOX_TEST_NAME=${test_file_path}
                        ${Python3_EXECUTABLE} -m tox
                        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/integrationv2)
            endif()
            set_property(TEST ${test_target} PROPERTY LABELS "integrationv2")
            set_property(TEST ${test_target} PROPERTY TIMEOUT 7200)
        endforeach()
    endif()
endif()

#install the s2n files
install(FILES ${API_HEADERS} DESTINATION "include/" COMPONENT Development)
install(FILES ${API_UNSTABLE_HEADERS} DESTINATION "include/s2n/unstable" COMPONENT Development)

if (UNIX AND NOT APPLE)
    include(GNUInstallDirs)
elseif(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

if (S2N_INSTALL_S2NC_S2ND)
  install(
    TARGETS s2nc s2nd RUNTIME DESTINATION bin
    )
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

install(FILES "cmake/modules/Findcrypto.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/cmake/modules/"
        COMPONENT Development)
