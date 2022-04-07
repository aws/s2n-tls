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
# Turn BUILD_TESTING=ON by default
include(CTest)

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
        "pq-crypto/bike_r1/*.h"
        "pq-crypto/bike_r2/*.h"
        "pq-crypto/bike_r3/*.h"
        "pq-crypto/sike_r1/*.h"
        "pq-crypto/kyber_r2/*.h"
        "pq-crypto/kyber_90s_r2/*.h"
        "pq-crypto/kyber_r3/*.h"
        "pq-crypto/sike_r3/*.h")

    # The SIKE r1 code #includes .c files directly; including sike_r1/*.c
    # here breaks the build due to duplicates. The SIKE r3 code does not have this issue.
    file(GLOB PQ_SRC
        "pq-crypto/*.c"
        "pq-crypto/bike_r1/*.c"
        "pq-crypto/bike_r2/*.c"
        "pq-crypto/bike_r3/*.c"
        "pq-crypto/sike_r1/fp_generic_r1.c"
        "pq-crypto/sike_r1/P503_r1.c"
        "pq-crypto/sike_r1/sike_r1_kem.c"
        "pq-crypto/sike_r1/fips202_r1.c"
        "pq-crypto/kyber_r2/*.c"
        "pq-crypto/kyber_90s_r2/*.c"
        "pq-crypto/kyber_r3/*.c"
        "pq-crypto/sike_r3/*.c")
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
set(SIKEP434R3_ASM_SUPPORTED false)
set(ADX_SUPPORTED false)

if(S2N_NO_PQ_ASM)
    message(STATUS "S2N_NO_PQ_ASM flag was detected - disabling PQ crypto assembly code")
else()
    enable_language(ASM)

    # sikep434r3
    try_compile(
            SIKEP434R3_ASM_SUPPORTED
            ${CMAKE_BINARY_DIR}
            SOURCES
            "${CMAKE_CURRENT_LIST_DIR}/tests/features/noop_main.c"
            "${CMAKE_CURRENT_LIST_DIR}/pq-crypto/sike_r3/sikep434r3.c"
            "${CMAKE_CURRENT_LIST_DIR}/pq-crypto/sike_r3/sikep434r3_fp_x64_asm.S"
    )

    if(SIKEP434R3_ASM_SUPPORTED)
        file(GLOB SIKEP434R3_ASM_SRC "pq-crypto/sike_r3/sikep434r3_fp_x64_asm.S")
        list(APPEND PQ_SRC ${SIKEP434R3_ASM_SRC})

        # The ADX instruction set is preferred for best performance, but not necessary.
        try_compile(
                ADX_SUPPORTED
                ${CMAKE_BINARY_DIR}
                SOURCES
                "${CMAKE_CURRENT_LIST_DIR}/tests/features/noop_main.c"
                "${CMAKE_CURRENT_LIST_DIR}/pq-crypto/sike_r3/sikep434r3.c"
                "${CMAKE_CURRENT_LIST_DIR}/pq-crypto/sike_r3/sikep434r3_fp_x64_asm.S"
                COMPILE_DEFINITIONS
                "-DS2N_ADX"
        )
    endif()

    # BIKE Round-3 code has several different optimizations which require
    # specific compiler flags to be supported by the compiler.
    # So for each needed instruction set extension we check if the compiler
    # supports it and set proper compiler flags to be added later to the
    # BIKE compilation units.
    if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "^(x86_64|amd64|AMD64)$")
        # First, check if the compiler supports the specific instruction set
        # extensions. For example, gcc-4 doesn't fully support AVX-512, while
        # gcc-7 doesn't support VPCLMUL extension.
        set(BIKE_R3_AVX2_FLAGS "-mavx2")
        try_compile(
                BIKE_R3_AVX2_SUPPORTED
                ${CMAKE_BINARY_DIR}
                SOURCES
                "${CMAKE_CURRENT_LIST_DIR}/tests/features/noop_main.c"
                "${CMAKE_CURRENT_LIST_DIR}/pq-crypto/bike_r3/gf2x_mul_avx2.c"
                CMAKE_FLAGS "-DINCLUDE_DIRECTORIES:STRING=${CMAKE_SOURCE_DIR}"
                COMPILE_DEFINITIONS "${BIKE_R3_AVX2_FLAGS} -DS2N_BIKE_R3_AVX2"
        )

        set(BIKE_R3_AVX512_FLAGS "-mavx512f -mavx512bw -mavx512dq")
        try_compile(
                BIKE_R3_AVX512_SUPPORTED
                ${CMAKE_BINARY_DIR}
                SOURCES
                "${CMAKE_CURRENT_LIST_DIR}/tests/features/noop_main.c"
                "${CMAKE_CURRENT_LIST_DIR}/pq-crypto/bike_r3/gf2x_mul_avx512.c"
                CMAKE_FLAGS "-DINCLUDE_DIRECTORIES:STRING=${CMAKE_SOURCE_DIR}"
                COMPILE_DEFINITIONS "${BIKE_R3_AVX512_FLAGS} -DS2N_BIKE_R3_AVX512"
        )

        set(BIKE_R3_PCLMUL_FLAGS "-mpclmul -msse2")
        try_compile(
                BIKE_R3_PCLMUL_SUPPORTED
                ${CMAKE_BINARY_DIR}
                SOURCES
                "${CMAKE_CURRENT_LIST_DIR}/tests/features/noop_main.c"
                "${CMAKE_CURRENT_LIST_DIR}/pq-crypto/bike_r3/gf2x_mul_base_pclmul.c"
                CMAKE_FLAGS "-DINCLUDE_DIRECTORIES:STRING=${CMAKE_SOURCE_DIR}"
                COMPILE_DEFINITIONS "${BIKE_R3_PCLMUL_FLAGS} -DS2N_BIKE_R3_PCLMUL"
        )

        set(BIKE_R3_VPCLMUL_FLAGS "-mvpclmulqdq -mavx512f -mavx512bw -mavx512dq")
        try_compile(
                BIKE_R3_VPCLMUL_SUPPORTED
                ${CMAKE_BINARY_DIR}
                SOURCES
                "${CMAKE_CURRENT_LIST_DIR}/tests/features/noop_main.c"
                "${CMAKE_CURRENT_LIST_DIR}/pq-crypto/bike_r3/gf2x_mul_base_vpclmul.c"
                CMAKE_FLAGS "-DINCLUDE_DIRECTORIES:STRING=${CMAKE_SOURCE_DIR}"
                COMPILE_DEFINITIONS "${BIKE_R3_VPCLMUL_FLAGS} -DS2N_BIKE_R3_VPCLMUL"
        )

        if(BIKE_R3_AVX2_SUPPORTED OR BIKE_R3_AVX512_SUPPORTED OR BIKE_R3_PCLMUL_SUPPORTED OR BIKE_R3_VPCLMUL_SUPPORTED)
            set(BIKE_R3_X86_64_OPT_SUPPORTED ON)
        endif()
    endif()

    # Kyber Round-3 code has several different optimizations which require
    # specific compiler flags to be supported by the compiler.
    # So for each needed instruction set extension we check if the compiler
    # supports it and set proper compiler flags to be added later to the
    # Kyber compilation units.
    if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "^(x86_64|amd64|AMD64)$")
    
        set(KYBER512R3_AVX2_BMI2_FLAGS "-mavx2 -mavx -mbmi2")
        try_compile(KYBER512R3_AVX2_BMI2_SUPPORTED
            ${CMAKE_BINARY_DIR}
            "${CMAKE_CURRENT_LIST_DIR}/tests/features/noop_main.c"
            COMPILE_DEFINITIONS ${KYBER512R3_AVX2_BMI2_FLAGS})
            
        if(KYBER512R3_AVX2_BMI2_SUPPORTED)
            set(KYBER512R3_AVX2_BMI2_OPT_SUPPORTED ON)
        endif()
    endif()
endif()

if(KYBER512R3_AVX2_BMI2_OPT_SUPPORTED)
    FILE(GLOB KYBER512R3_AVX2_BMI2_ASM_SRCS "pq-crypto/kyber_r3/*_avx2.S")
    list(APPEND PQ_SRC ${KYBER512R3_AVX2_BMI2_ASM_SRCS})
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

# Determine if features.h is available
try_compile(
        S2N_FEATURES_AVAILABLE
        ${CMAKE_BINARY_DIR}
        SOURCES "${CMAKE_CURRENT_LIST_DIR}/tests/features/features.c"
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

# Determine if madvise() is available
try_compile(
        MADVISE_SUPPORTED
        ${CMAKE_BINARY_DIR}
        SOURCES "${CMAKE_CURRENT_LIST_DIR}/tests/features/madvise.c"
        COMPILE_DEFINITIONS "-Werror"
)

# Determine if minherit() is available
try_compile(
        MINHERIT_SUPPORTED
        ${CMAKE_BINARY_DIR}
        SOURCES "${CMAKE_CURRENT_LIST_DIR}/tests/features/minherit.c"
        COMPILE_DEFINITIONS "-Werror"
)

# Determine if clone() is available
try_compile(
        CLONE_SUPPORTED
        ${CMAKE_BINARY_DIR}
        SOURCES "${CMAKE_CURRENT_LIST_DIR}/tests/features/clone.c"
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

# Compiling the unit tests rely on S2N_TEST_IN_FIPS_MODE to be set correctly
if(S2N_FIPS)
    add_definitions(-DS2N_TEST_IN_FIPS_MODE)
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

target_compile_options(${PROJECT_NAME} PRIVATE -pedantic -std=gnu99 -Wall -Wimplicit -Wunused -Wcomment -Wchar-subscripts
        -Wuninitialized -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security
        -Wno-missing-braces -Wa,--noexecstack
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
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_NO_PQ)
endif()

if(SIKEP434R3_ASM_SUPPORTED)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_SIKE_P434_R3_ASM)
    message(STATUS "Enabling SIKEP434R3 assembly code")
endif()

if(BIKE_R3_X86_64_OPT_SUPPORTED)
    # If any of the BIKE_R3 x86_64 optimizations is supported (this was checked
    # earlier in the file), we add the required compile flags to files that
    # contain the optimized code.

    message(STATUS "Enabling BIKE_R3 x86_64 optimizations")

    if(BIKE_R3_AVX2_SUPPORTED)
        message(STATUS "\t Enabling BIKE_R3_AVX2")
        FILE(GLOB BIKE_R3_AVX2_SRCS "pq-crypto/bike_r3/*_avx2.c")
        set_source_files_properties(${BIKE_R3_AVX2_SRCS} PROPERTIES COMPILE_FLAGS -mavx2)
        target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_BIKE_R3_AVX2)
    endif()

    if(BIKE_R3_AVX512_SUPPORTED)
        message(STATUS "\t Enabling BIKE_R3_AVX512")
        FILE(GLOB BIKE_R3_AVX512_SRCS "pq-crypto/bike_r3/*_avx512.c")
        set_source_files_properties(${BIKE_R3_AVX512_SRCS} PROPERTIES COMPILE_FLAGS ${BIKE_R3_AVX512_FLAGS})
        target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_BIKE_R3_AVX512)
    endif()

    if(BIKE_R3_PCLMUL_SUPPORTED)
        message(STATUS "\t Enabling BIKE_R3_PCLMUL")
        FILE(GLOB BIKE_R3_PCLMUL_SRCS "pq-crypto/bike_r3/*_pclmul.c")
        set_source_files_properties(${BIKE_R3_PCLMUL_SRCS} PROPERTIES COMPILE_FLAGS ${BIKE_R3_PCLMUL_FLAGS})
        target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_BIKE_R3_PCLMUL)
    endif()

    if(BIKE_R3_VPCLMUL_SUPPORTED)
        message(STATUS "\t Enabling BIKE_R3_VPCLMUL")
        FILE(GLOB BIKE_R3_VPCLMUL_SRCS "pq-crypto/bike_r3/*_vpclmul.c")
        set_source_files_properties(${BIKE_R3_VPCLMUL_SRCS} PROPERTIES COMPILE_FLAGS ${BIKE_R3_VPCLMUL_FLAGS})
        target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_BIKE_R3_VPCLMUL)
    endif()
endif()

if(KYBER512R3_AVX2_BMI2_OPT_SUPPORTED)
    FILE(GLOB KYBER512R3_AVX2_BMI2_SRCS "pq-crypto/kyber_r3/*.c")
    set_source_files_properties(${KYBER512R3_AVX2_BMI2_SRCS} PROPERTIES COMPILE_FLAGS ${KYBER512R3_AVX2_BMI2_FLAGS})
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_KYBER512R3_AVX2_BMI2)

    message(STATUS "Enabling Kyber_R3 x86_64 optimizations")
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

if(S2N_FEATURES_AVAILABLE)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_FEATURES_AVAILABLE)
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

if (MADVISE_SUPPORTED)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_MADVISE_SUPPORTED)
    message(STATUS "madvise() support detected")
endif()

if (MINHERIT_SUPPORTED)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_MINHERIT_SUPPORTED)
    message(STATUS "minherit() support detected")
endif()

if (CLONE_SUPPORTED)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_CLONE_SUPPORTED)
    message(STATUS "clone() support detected")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

#work around target differences
if (TARGET crypto)
    message(STATUS "S2N found target: crypto")
    set(LINK_LIB "crypto")
else()
    find_package(crypto REQUIRED)
    message("Using libcrypto from the cmake path.")
    set(LINK_LIB "AWS::crypto")
endif()

# Determine if EVP_md5_sha1 is available in libcrypto
try_compile(
        LIBCRYPTO_SUPPORTS_EVP_MD5_SHA1_HASH
        ${CMAKE_BINARY_DIR}
        SOURCES "${CMAKE_CURRENT_LIST_DIR}/tests/features/evp_md5_sha1.c"
        LINK_LIBRARIES ${LINK_LIB} ${OS_LIBS}
)
if (LIBCRYPTO_SUPPORTS_EVP_MD5_SHA1_HASH)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_LIBCRYPTO_SUPPORTS_EVP_MD5_SHA1_HASH)
endif()

# Determine if EVP_MD_CTX_set_pkey_ctx is available in libcrypto
try_compile(
        LIBCRYPTO_SUPPORTS_EVP_MD_CTX_SET_PKEY_CTX
        ${CMAKE_BINARY_DIR}
        SOURCES "${CMAKE_CURRENT_LIST_DIR}/tests/features/evp_md_ctx_set_pkey_ctx.c"
        LINK_LIBRARIES ${LINK_LIB} ${OS_LIBS}
        CMAKE_FLAGS ${ADDITIONAL_FLAGS}
)

if (LIBCRYPTO_SUPPORTS_EVP_MD_CTX_SET_PKEY_CTX)
    target_compile_options(${PROJECT_NAME} PUBLIC -DS2N_LIBCRYPTO_SUPPORTS_EVP_MD_CTX_SET_PKEY_CTX)
endif()

if (S2N_INTERN_LIBCRYPTO)
    if (NOT crypto_STATIC_LIBRARY)
        message(FATAL_ERROR "libcrypto interning requires a static build of libcrypto.a to be available")
    endif()

    # Don't call link_target_libraries here, just make sure the libcrypto include dir is in the path
    include_directories("${crypto_INCLUDE_DIR}")

    add_custom_command(
        OUTPUT libcrypto.symbols
        COMMAND
          # copy the static version of libcrypto
          cp ${crypto_STATIC_LIBRARY} s2n_libcrypto.a &&
          # dump all of the symbols and prefix them with `s2n$`
          bash -c "nm s2n_libcrypto.a | awk '/ [A-Z] /{print $3\" s2n$\"$3}' | sort | uniq > libcrypto.symbols" &&
          # redefine the libcrypto libary symbols
          objcopy --redefine-syms libcrypto.symbols s2n_libcrypto.a &&
          rm -rf s2n_libcrypto &&
          mkdir s2n_libcrypto &&
          cd s2n_libcrypto &&
          # extract libcrypto objects from the archive
          ar x ../s2n_libcrypto.a &&
          # rename all of the object files so we don't have any object name collisions
          bash -c "find . -name '*.o' -type f -print0 | xargs -0 -n1 -- basename | xargs -I{} mv {} s2n_crypto__{}"
        VERBATIM
    )

    add_custom_target(s2n_libcrypto ALL
      DEPENDS libcrypto.symbols
    )
    add_dependencies(${PROJECT_NAME} s2n_libcrypto)

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
              bash -c "ar -r lib/libs2n.a s2n_libcrypto/*.o"
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
    file(GLOB TESTLIB_HEADERS "tests/testlib/*.h" "tests/s2n_test.h")

    add_library(testss2n STATIC ${TESTLIB_HEADERS} ${TESTLIB_SRC})
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

    target_include_directories(s2nc PRIVATE api)
    target_compile_options(s2nc PRIVATE -std=gnu99 -D_POSIX_C_SOURCE=200112L)

    add_executable(s2nd "bin/s2nd.c" "bin/echo.c" "bin/https.c" "bin/common.c")
    target_link_libraries(s2nd ${PROJECT_NAME})

    target_include_directories(s2nd PRIVATE api)
    target_compile_options(s2nd PRIVATE -std=gnu99 -D_POSIX_C_SOURCE=200112L)

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

install(FILES "cmake/modules/Findcrypto.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/cmake/modules/"
        COMPONENT Development)
