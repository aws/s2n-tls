project(bike1-l1)

file(GLOB BIKE_HEADERS
    "*.h"
    "../pq-random.h"
    "../pq-utils.h"
)

file(GLOB BIKE_SOURCE
    "*.c"
)

add_library(bike1-l1 ${BIKE_HEADERS} ${BIKE_SOURCE})
add_library(bike1-l1-nist-known-answer-rng ${BIKE_HEADERS} ${BIKE_SOURCE})
set_target_properties(bike1-l1 PROPERTIES PUBLIC_HEADER bike1_l1_kem.h)

# Only include the single header file that declares the public API
target_include_directories(bike1-l1 PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/bike1_l1_kem.h> $<INSTALL_INTERFACE:include>)

target_compile_options(bike1-l1 PUBLIC -std=c99 -Wno-missing-braces -Wno-missing-field-initializers -DBIKE1=1 -DPARAM64=1)

target_compile_options(bike1-l1-nist-known-answer-rng PUBLIC -std=c99 -Wno-missing-braces -Wno-missing-field-initializers -DBIKE1=1 -DPARAM64=1 -DNIST_RNG_FOR_UNIT_TEST)

install (
        TARGETS bike1-l1
        EXPORT "bike1-l1Targets"
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION "${INSTALL_INCLUDE_DIR}"
        COMPONENT dev
)
