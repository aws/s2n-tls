file(GLOB GENERAL_HEADERS
    "*.h"
)

file(GLOB SIKE_HEADERS
    "sike/*.h"
)

file(GLOB GENERAL_SRC
    "*.c"
)

# The SIKE code #includes .c files directly, including all sike/*.c breaks the build due to duplicates
file(GLOB SIKE_SRC
    "sike/fp_generic.c"
    "sike/P503.c"
    "sike/sike_p503_kem.c"
    "sike/fips202.c"
)

file(GLOB S2N_PQ_CRYPTO_HEADERS
    ${GENERAL_HEADERS}
    ${SIKE_HEADERS}
)

file(GLOB S2N_PQ_CRYPTO_SRC
    ${GENERAL_SRC}
    ${SIKE_SRC}
)

##be nice to visual studio users
if(MSVC)
    source_group("Header Files\\pq-crypto\\general" FILES ${GENERAL_HEADERS})
    source_group("Header Files\\pq-crypto\\sike" FILES ${SIKE_HEADERS})

    source_group("Source Files\\pq-crypto\\general" FILES ${GENERAL_SRC})
    source_group("Source Files\\pq-crypto\\sike" FILES ${SIKE_SRC})
endif()

add_library(s2n_pq_crypto ${S2N_PQ_CRYPTO_HEADERS} ${S2N_PQ_CRYPTO_SRC})
set_target_properties(s2n_pq_crypto PROPERTIES LINKER_LANGUAGE C)

# This library depends on S2N utils (blob)
include_directories ("${PROJECT_SOURCE_DIR}")

set(CMAKE_C_FLAGS_DEBUGOPT "")

target_compile_options(s2n_pq_crypto PRIVATE -pedantic -std=c99 -Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts
        -Wuninitialized -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security
        -Wno-missing-braces)
target_compile_options(s2n_pq_crypto PUBLIC -fPIC)

# Copied from parent CmakeLists.txt
target_compile_definitions(s2n_pq_crypto PRIVATE -D_POSIX_C_SOURCE=200809L)
if(CMAKE_BUILD_TYPE MATCHES Release)
    target_compile_definitions(s2n_pq_crypto PRIVATE -D_FORTIFY_SOURCE=2)
endif()

if(NO_STACK_PROTECTOR)
    target_compile_options(s2n_pq_crypto PRIVATE -Wstack-protector -fstack-protector-all)
endif()

if(S2N_UNSAFE_FUZZING_MODE)
    target_compile_options(s2n_pq_crypto PRIVATE -fsanitize-coverage=trace-pc-guard -fsanitize=address,undefined,leak)
endif()


