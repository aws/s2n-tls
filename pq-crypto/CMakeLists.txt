file(GLOB GENERAL_HEADERS
    "*.h"
)

file(GLOB BIKE_HEADERS
    "bike/*.h"
)

file(GLOB SIKE_HEADERS
    "sike/*.h"
)

file(GLOB GENERAL_SRC
    "*.c"
)

file(GLOB BIKE_SRC
    "bike/*.c"
)

file(GLOB SIKE_SRC
    "sike/fp_generic.c"
    "sike/P503.c"
    "sike/sike_p503_kem.c"
    "sike/fips202.c"
)

file(GLOB S2N_PQ_CRYPTO_HEADERS
    ${GENERAL_HEADERS}
    ${BIKE_HEADERS}
    ${SIKE_HEADERS}
)

file(GLOB S2N_PQ_CRYPTO_SRC
    ${GENERAL_SRC}
    ${BIKE_SRC}
    ${SIKE_SRC}
)

##be nice to visual studio users
if(MSVC)
    source_group("Header Files\\pq-crypto\\general" FILES ${GENERAL_HEADERS})
    source_group("Header Files\\pq-crypto\\bike" FILES ${BIKE_HEADERS})
    source_group("Header Files\\pq-crypto\\sike" FILES ${SIKE_HEADERS})

    source_group("Source Files\\pq-crypto\\general" FILES ${GENERAL_SRC})
    source_group("Source Files\\pq-crypto\\bike" FILES ${BIKE_SRC})
    source_group("Source Files\\pq-crypto\\sike" FILES ${SIKE_SRC})
endif()

add_library(s2n_pq_crypto ${S2N_PQ_CRYPTO_HEADERS} ${S2N_PQ_CRYPTO_SRC})
set_target_properties(s2n_pq_crypto PROPERTIES LINKER_LANGUAGE C)

# This library depends on S2N utils (blob)
include_directories ("${PROJECT_SOURCE_DIR}")

set(CMAKE_C_FLAGS_DEBUGOPT "")

# We intentionally do not use -pedantic here because this will make SIKE compilation failed (TODO: fix)
target_compile_options(s2n_pq_crypto PRIVATE -std=c99 -Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security)
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


