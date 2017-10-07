cmake_minimum_required (VERSION 3.0)
project (s2n)

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

file(GLOB STUFFER_SOURCE
    "stuffer/*.c"
)

file(GLOB TLS_SRC
    "tls/*.c"
)

file(GLOB UTILS_SRC
    "utils/*.c"
)

##be nice to visutal studio users
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
 
add_library(s2nStatic STATIC ${S2N_HEADERS} ${S2N_SRC})
add_library(s2nShared SHARED ${S2N_HEADERS} ${S2N_SRC})
set_target_properties(s2nStatic PROPERTIES OUTPUT_NAME s2n)
set_target_properties(s2nShared PROPERTIES OUTPUT_NAME s2n)

set_target_properties(s2nStatic PROPERTIES LINKER_LANGUAGE C)
set_target_properties(s2nShared PROPERTIES LINKER_LANGUAGE C) 

set(CMAKE_C_FLAGS_DEBUGOPT "")

target_compile_options(s2nStatic PRIVATE -std=c99 -pedantic -Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security)

target_compile_options(s2nShared PRIVATE -std=c99 -pedantic -Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security)

target_compile_definitions(s2nStatic PRIVATE -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2)
target_compile_definitions(s2nShared PRIVATE -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2)

target_compile_options(s2nStatic PUBLIC -fPIC -fgnu89-inline)    
target_compile_options(s2nShared PUBLIC -fPIC -fgnu89-inline)

if(NO_STACK_PROTECTOR)
    target_compile_options(s2nStatic PRIVATE -Wstack-protector -fstack-protector-all)
    target_compile_options(s2nShared PRIVATE -Wstack-protector -fstack-protector-all)
endif()

if(S2N_UNSAFE_FUZZING_MODE)
    target_compile_options(s2nStatic PRIVATE -fsanitize-coverage=trace-pc-guard -fsanitize=address,undefined,leak)
    target_compile_options(s2nShared PRIVATE -fsanitize-coverage=trace-pc-guard -fsanitize=address,undefined,leak)
endif()

if(NOT LIBCRYPTO_ROOT)
    find_package(OpenSSL)   
    target_include_directories(s2nStatic PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_include_directories(s2nShared PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(s2nStatic PRIVATE ${OS_LIBS} OpenSSL::Crypto)
    target_link_libraries(s2nShared PRIVATE ${OS_LIBS} OpenSSL::Crypto)
else()
    target_include_directories(s2nStatic PRIVATE ${LIBCRYPTO_ROOT}/include)
    target_include_directories(s2nShared PRIVATE ${LIBCRYPTO_ROOT}/include)
    link_directories(${LIBCRYPTO_ROOT})
    target_link_libraries(s2nStatic PRIVATE ${OS_LIBS} crypto)
    target_link_libraries(s2nShared PRIVATE ${OS_LIBS} crypto)
endif()

target_include_directories(s2nStatic PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(s2nShared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(s2nStatic PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/api)
target_include_directories(s2nShared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/api)
target_link_libraries(s2nStatic PRIVATE ${OS_LIBS} OpenSSL::Crypto)
target_link_libraries(s2nShared PRIVATE ${OS_LIBS} OpenSSL::Crypto) 

file(GLOB TESTLIB_SRC "tests/testlib/*.c")
file(GLOB TESTLIB_HEADERS "tests/testlib/*.h")

add_library(testss2n SHARED ${TESTLIB_HEADERS} ${TESTLIB_SRC})
target_include_directories(testss2n PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests)
target_link_libraries(testss2n PRIVATE s2nShared)
# file(GLOB TEST_HDRS "tests/*.h")
# file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})
   
# include_directories(${CMAKE_CURRENT_SOURCE_DIR}/tests)
# add_executable(aws-io-tests ${TESTS} tests/event_loop_test.c)
# target_link_libraries(aws-io-tests aws-io)
# set_target_properties(aws-io-tests PROPERTIES LINKER_LANGUAGE C)
# set_property(TARGET aws-io-tests PROPERTY C_STANDARD 99)

#add_custom_command(TARGET aws-io-tests PRE_BUILD
#        COMMAND ${CMAKE_COMMAND} -E copy_directory
#        ${CMAKE_CURRENT_SOURCE_DIR}/tests/resources ${CMAKE_CURRENT_BINARY_DIR})
 
# include(CTest)
# enable_testing()
 
# install (FILES ${AWS_IO_HEADERS} DESTINATION "include/aws/io")
# install (
 #         TARGETS ${PROJECT_NAME}
 #         EXPORT "${PROJECT_NAME}-targets"
 #         ARCHIVE DESTINATION lib
 #         LIBRARY DESTINATION lib
 #         COMPONENT library     
 #)
