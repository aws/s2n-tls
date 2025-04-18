set(SCRIPT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/runFuzzTest.sh")
file(GLOB FUZZ_TEST_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

file(GLOB TESTLIB_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../testlib/*.c")
file(GLOB TESTLIB_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/../testlib/*.h" "${CMAKE_CURRENT_SOURCE_DIR}/../s2n_test.h")

add_library(fuzztest SHARED ${TESTLIB_SRC})
target_include_directories(fuzztest PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(fuzztest PUBLIC s2n)  # assumes main lib is called `s2n`

# Set timeout
if(DEFINED ENV{FUZZ_TIMEOUT_SEC})
    set(FUZZ_TIMEOUT_SEC $ENV{FUZZ_TIMEOUT_SEC})
else()
    set(FUZZ_TIMEOUT_SEC 60)
endif()

file(GLOB LIBRARY_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/LD_PRELOAD/*.c")
foreach(SRC ${LIBRARY_SRCS})
    get_filename_component(LIB_NAME ${SRC} NAME_WE)
    add_library(${LIB_NAME} SHARED ${SRC})
    target_include_directories(${LIB_NAME} PRIVATE 
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/api
    )
endforeach()

# Detect clang
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set(USE_LIBFUZZER TRUE)
else()
    message(WARNING "Fuzz tests require Clang with libFuzzer support. Build may fail.")
endif()

foreach(src ${FUZZ_TEST_SRCS})
    get_filename_component(TEST_NAME ${src} NAME_WE)

    add_executable(${TEST_NAME} ${src})

    if(USE_LIBFUZZER)
        target_compile_options(${TEST_NAME} PRIVATE 
            -g -Wno-unknown-pragmas -Wno-unused-result -fsanitize=fuzzer-no-link
        )
        target_link_options(${TEST_NAME} PRIVATE 
            -fsanitize=fuzzer -lstdc++
        )
    else()
        target_compile_options(${TEST_NAME} PRIVATE -g)
    endif()

    target_link_libraries(${TEST_NAME} PRIVATE fuzztest)

    add_test(NAME ${TEST_NAME}
        COMMAND ${CMAKE_COMMAND} -E env
            bash ${SCRIPT_PATH} 
            ${TEST_NAME} 
            ${FUZZ_TIMEOUT_SEC} 
            ${CMAKE_CURRENT_SOURCE_DIR}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    set_property(TEST ${TEST_NAME} PROPERTY LABELS "fuzz")
endforeach()
