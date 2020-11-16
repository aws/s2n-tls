# - Try to find LibCrypto include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(LibCrypto)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
# Variables defined by this module:
#
#  LibCrypto_FOUND             System has libcrypto, include and library dirs found
#  LibCrypto_INCLUDE_DIR       The crypto include directories.
#  LibCrypto_LIBRARY           The crypto library, depending on the value of BUILD_SHARED_LIBS.
#  LibCrypto_SHARED_LIBRARY    The path to libcrypto.so
#  LibCrypto_STATIC_LIBRARY    The path to libcrypto.a

find_path(LibCrypto_INCLUDE_DIR
    NAMES openssl/crypto.h
    HINTS
        ${CMAKE_PREFIX_PATH}/include 
        ${CMAKE_INSTALL_PREFIX}/include
        /usr/local/opt/openssl/include
    )
find_library(LibCrypto_SHARED_LIBRARY
    NAMES libcrypto.so libcrypto.dylib
    HINTS
    ${CMAKE_PREFIX_PATH}/build/crypto
    ${CMAKE_PREFIX_PATH}/build
    ${CMAKE_PREFIX_PATH}
    ${CMAKE_PREFIX_PATH}/lib64
    ${CMAKE_PREFIX_PATH}/lib 
    ${CMAKE_INSTALL_PREFIX}/build/crypto
    ${CMAKE_INSTALL_PREFIX}/build
    ${CMAKE_INSTALL_PREFIX}
    ${CMAKE_INSTALL_PREFIX}/lib64
    ${CMAKE_INSTALL_PREFIX}/lib
    /usr/local/opt/openssl/lib
    /usr/lib64
    )
find_library(LibCrypto_STATIC_LIBRARY
    NAMES libcrypto.a
    HINTS 
    ${CMAKE_PREFIX_PATH}/build/crypto
    ${CMAKE_PREFIX_PATH}/build
    ${CMAKE_PREFIX_PATH}
    ${CMAKE_PREFIX_PATH}/lib64
    ${CMAKE_PREFIX_PATH}/lib   
    ${CMAKE_INSTALL_PREFIX}/build/crypto
    ${CMAKE_INSTALL_PREFIX}/build
    ${CMAKE_INSTALL_PREFIX}
    ${CMAKE_INSTALL_PREFIX}/lib64
    ${CMAKE_INSTALL_PREFIX}/lib
    /usr/local/opt/openssl/lib
    /usr/lib64
    )

if (BUILD_SHARED_LIBS)
    set(LibCrypto_LIBRARY ${LibCrypto_SHARED_LIBRARY})
else()
    set(LibCrypto_LIBRARY ${LibCrypto_STATIC_LIBRARY})
endif()


include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibCrypto DEFAULT_MSG
    LibCrypto_LIBRARY
    LibCrypto_INCLUDE_DIR
    )

mark_as_advanced(
    LibCrypto_ROOT_DIR
    LibCrypto_INCLUDE_DIR
    LibCrypto_LIBRARY
    LibCrypto_SHARED_LIBRARY
    LibCrypto_STATIC_LIBRARY
    )

# some versions of cmake have a super esoteric bug around capitalization differences between
# find dependency and find package, just avoid that here by checking and
# setting both.
if(LIBCRYPTO_FOUND OR LibCrypto_FOUND)
    set(LIBCRYPTO_FOUND true)
    set(LibCrypto_FOUND true)

    message(STATUS "LibCrypto Include Dir: ${LibCrypto_INCLUDE_DIR}")
    message(STATUS "LibCrypto Shared Lib:  ${LibCrypto_SHARED_LIBRARY}")
    message(STATUS "LibCrypto Static Lib:  ${LibCrypto_STATIC_LIBRARY}")
    if (NOT TARGET LibCrypto::Crypto AND
        (EXISTS "${LibCrypto_LIBRARY}")
        )
        set(THREADS_PREFER_PTHREAD_FLAG ON)
        find_package(Threads REQUIRED)
        add_library(LibCrypto::Crypto UNKNOWN IMPORTED)
        set_target_properties(LibCrypto::Crypto PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${LibCrypto_INCLUDE_DIR}")
        set_target_properties(LibCrypto::Crypto PROPERTIES
            IMPORTED_LINK_INTERFACE_LANGUAGES "C"
            IMPORTED_LOCATION "${LibCrypto_LIBRARY}")
        add_dependencies(LibCrypto::Crypto Threads::Threads)
    endif()
endif()
